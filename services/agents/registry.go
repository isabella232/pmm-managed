// pmm-managed
// Copyright (C) 2017 Percona LLC
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package agents contains business logic of working with pmm-agent.
package agents

import (
	"context"
	"fmt"
	"runtime/pprof"
	"sort"
	"sync"
	"time"

	"github.com/AlekSi/pointer"
	"github.com/golang/protobuf/ptypes"
	"github.com/percona/pmm/api/agentpb"
	"github.com/percona/pmm/api/inventorypb"
	"github.com/percona/pmm/version"
	"github.com/pkg/errors"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/reform.v1"

	"github.com/percona/pmm-managed/models"
	"github.com/percona/pmm-managed/services/agents/channel"
	"github.com/percona/pmm-managed/utils/logger"
)

const (
	prometheusNamespace = "pmm_managed"
	prometheusSubsystem = "agents"
)

var (
	defaultActionTimeout      = ptypes.DurationProto(10 * time.Second)
	defaultQueryActionTimeout = ptypes.DurationProto(15 * time.Second) // should be less than checks.resultTimeout
)

type pmmAgentInfo struct {
	channel *channel.Channel
	id      string
	kick    chan struct{}
}

// Registry keeps track of all connected pmm-agents.
//
// TODO Split into several types https://jira.percona.com/browse/PMM-4932
type Registry struct {
	db         *reform.DB
	prometheus prometheusService
	vmdb       prometheusService
	qanClient  qanClient

	rw     sync.RWMutex
	agents map[string]*pmmAgentInfo // id -> info

	roster *roster

	sharedMetrics *channel.SharedChannelMetrics
	mConnects     prom.Counter
	mDisconnects  *prom.CounterVec
	mRoundTrip    prom.Summary
	mClockDrift   prom.Summary
}

// NewRegistry creates a new registry with given database connection.
func NewRegistry(db *reform.DB, qanClient qanClient, prometheus, vmdb prometheusService) *Registry {
	r := &Registry{
		db:         db,
		prometheus: prometheus,
		vmdb:       vmdb,
		qanClient:  qanClient,

		agents: make(map[string]*pmmAgentInfo),

		roster: newRoster(),

		sharedMetrics: channel.NewSharedMetrics(),
		mConnects: prom.NewCounter(prom.CounterOpts{
			Namespace: prometheusNamespace,
			Subsystem: prometheusSubsystem,
			Name:      "connects_total",
			Help:      "A total number of pmm-agent connects.",
		}),
		mDisconnects: prom.NewCounterVec(prom.CounterOpts{
			Namespace: prometheusNamespace,
			Subsystem: prometheusSubsystem,
			Name:      "disconnects_total",
			Help:      "A total number of pmm-agent disconnects.",
		}, []string{"reason"}),
		mRoundTrip: prom.NewSummary(prom.SummaryOpts{
			Namespace:  prometheusNamespace,
			Subsystem:  prometheusSubsystem,
			Name:       "round_trip_seconds",
			Help:       "Round-trip time.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		}),
		mClockDrift: prom.NewSummary(prom.SummaryOpts{
			Namespace:  prometheusNamespace,
			Subsystem:  prometheusSubsystem,
			Name:       "clock_drift_seconds",
			Help:       "Clock drift.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		}),
	}

	// initialize metrics with labels
	r.mDisconnects.WithLabelValues("unknown")

	return r
}

// IsConnected returns true if pmm-agent with given ID is currently connected, false otherwise.
func (r *Registry) IsConnected(pmmAgentID string) bool {
	_, err := r.get(pmmAgentID)
	return err == nil
}

// Run takes over pmm-agent gRPC stream and runs it until completion.
func (r *Registry) Run(stream agentpb.Agent_ConnectServer) error {
	r.mConnects.Inc()
	disconnectReason := "unknown"
	defer func() {
		r.mDisconnects.WithLabelValues(disconnectReason).Inc()
	}()

	ctx := stream.Context()
	l := logger.Get(ctx)
	agent, err := r.register(stream)
	if err != nil {
		disconnectReason = "auth"
		return err
	}
	defer func() {
		l.Infof("Disconnecting client: %s.", disconnectReason)
	}()

	// send first SetStateRequest concurrently with handling ping from agent
	go r.SendSetStateRequest(ctx, agent.id)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.ping(ctx, agent)

		case <-agent.kick:
			l.Warn("Kicked.")
			disconnectReason = "kicked"
			err = status.Errorf(codes.Aborted, "Another pmm-agent with ID %q connected to the server.", agent.id)
			return err

		case req := <-agent.channel.Requests():
			if req == nil {
				disconnectReason = "done"
				return agent.channel.Wait()
			}

			switch p := req.Payload.(type) {
			case *agentpb.Ping:
				agent.channel.SendResponse(&channel.ServerResponse{
					ID: req.ID,
					Payload: &agentpb.Pong{
						CurrentTime: ptypes.TimestampNow(),
					},
				})

			case *agentpb.StateChangedRequest:
				pprof.Do(ctx, pprof.Labels("request", "StateChangedRequest"), func(ctx context.Context) {
					if err := r.stateChanged(ctx, p); err != nil {
						l.Errorf("%+v", err)
					}

					agent.channel.SendResponse(&channel.ServerResponse{
						ID:      req.ID,
						Payload: new(agentpb.StateChangedResponse),
					})
				})

			case *agentpb.QANCollectRequest:
				pprof.Do(ctx, pprof.Labels("request", "QANCollectRequest"), func(ctx context.Context) {
					if err := r.qanClient.Collect(ctx, p.MetricsBucket); err != nil {
						l.Errorf("%+v", err)
					}

					agent.channel.SendResponse(&channel.ServerResponse{
						ID:      req.ID,
						Payload: new(agentpb.QANCollectResponse),
					})
				})

			case *agentpb.ActionResultRequest:
				// TODO: PMM-3978: In the future we need to merge action parts before send it to storage.
				err := models.ChangeActionResult(r.db.Querier, p.ActionId, agent.id, p.Error, string(p.Output), p.Done)
				if err != nil {
					l.Warnf("Failed to change action: %+v", err)
				}

				if !p.Done && p.Error != "" {
					l.Warnf("Action was done with an error: %v.", p.Error)
				}

				agent.channel.SendResponse(&channel.ServerResponse{
					ID:      req.ID,
					Payload: new(agentpb.ActionResultResponse),
				})

			case nil:
				l.Warnf("Unexpected request: %v.", req)
				disconnectReason = "unimplemented"
				return status.Error(codes.Unimplemented, "Unexpected request payload.")
			}
		}
	}
}

func (r *Registry) register(stream agentpb.Agent_ConnectServer) (*pmmAgentInfo, error) {
	ctx := stream.Context()
	l := logger.Get(ctx)
	agentMD, err := agentpb.ReceiveAgentConnectMetadata(stream)
	if err != nil {
		return nil, err
	}
	runsOnNodeID, err := authenticate(agentMD, r.db.Querier)
	if err != nil {
		l.Warnf("Failed to authenticate connected pmm-agent %+v.", agentMD)
		return nil, err
	}
	l.Infof("Connected pmm-agent: %+v.", agentMD)

	serverMD := agentpb.ServerConnectMetadata{
		AgentRunsOnNodeID: runsOnNodeID,
		ServerVersion:     version.Version,
	}
	l.Debugf("Sending metadata: %+v.", serverMD)
	if err = agentpb.SendServerConnectMetadata(stream, &serverMD); err != nil {
		return nil, err
	}

	r.rw.Lock()
	defer r.rw.Unlock()

	// do not use r.get() - r.rw is already locked
	if agent := r.agents[agentMD.ID]; agent != nil {
		r.roster.clear(agentMD.ID)
		close(agent.kick)
	}

	agent := &pmmAgentInfo{
		channel: channel.New(stream, r.sharedMetrics),
		id:      agentMD.ID,
		kick:    make(chan struct{}),
	}
	r.agents[agentMD.ID] = agent
	return agent, nil
}

func authenticate(md *agentpb.AgentConnectMetadata, q *reform.Querier) (string, error) {
	if md.ID == "" {
		return "", status.Error(codes.PermissionDenied, "Empty Agent ID.")
	}

	agent, err := models.FindAgentByID(q, md.ID)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return "", status.Errorf(codes.PermissionDenied, "No Agent with ID %q.", md.ID)
		}
		return "", errors.Wrap(err, "failed to find agent")
	}

	if agent.AgentType != models.PMMAgentType {
		return "", status.Errorf(codes.PermissionDenied, "No pmm-agent with ID %q.", md.ID)
	}

	if pointer.GetString(agent.RunsOnNodeID) == "" {
		return "", status.Errorf(codes.PermissionDenied, "Can't get 'runs_on_node_id' for pmm-agent with ID %q.", md.ID)
	}

	agent.Version = &md.Version
	if err := q.Update(agent); err != nil {
		return "", errors.Wrap(err, "failed to update agent")
	}

	return pointer.GetString(agent.RunsOnNodeID), nil
}

// Kick disconnects pmm-agent with given ID.
func (r *Registry) Kick(ctx context.Context, pmmAgentID string) {
	// We do not check that pmmAgentID is in fact ID of existing pmm-agent because
	// it may be already deleted from the database, that's why we disconnect it.

	r.rw.Lock()
	defer r.rw.Unlock()

	// do not use r.get() - r.rw is already locked
	l := logger.Get(ctx)
	agent := r.agents[pmmAgentID]
	if agent == nil {
		l.Infof("pmm-agent with ID %q is not connected.", pmmAgentID)
		return
	}
	l.Infof("pmm-agent with ID %q is connected, kicking.", pmmAgentID)
	delete(r.agents, pmmAgentID)
	r.roster.clear(pmmAgentID)
	close(agent.kick)
}

// ping sends Ping message to given Agent, waits for Pong and observes round-trip time and clock drift.
func (r *Registry) ping(ctx context.Context, agent *pmmAgentInfo) {
	l := logger.Get(ctx)
	start := time.Now()
	resp := agent.channel.SendRequest(new(agentpb.Ping))
	if resp == nil {
		return
	}
	roundtrip := time.Since(start)
	agentTime, err := ptypes.Timestamp(resp.(*agentpb.Pong).CurrentTime)
	if err != nil {
		l.Errorf("Failed to decode Pong.current_time: %s.", err)
		return
	}
	clockDrift := agentTime.Sub(start) - roundtrip/2
	if clockDrift < 0 {
		clockDrift = -clockDrift
	}
	l.Infof("Round-trip time: %s. Estimated clock drift: %s.", roundtrip, clockDrift)
	r.mRoundTrip.Observe(roundtrip.Seconds())
	r.mClockDrift.Observe(clockDrift.Seconds())
}

func updateAgentStatus(ctx context.Context, q *reform.Querier, agentID string, status inventorypb.AgentStatus, listenPort uint32) error {
	l := logger.Get(ctx)
	l.Debugf("updateAgentStatus: %s %s %d", agentID, status, listenPort)

	agent := &models.Agent{AgentID: agentID}
	err := q.Reload(agent)

	// TODO set ListenPort to NULL when agent is done?
	// https://jira.percona.com/browse/PMM-4932

	// FIXME that requires more investigation: https://jira.percona.com/browse/PMM-4932
	if err == reform.ErrNoRows {
		l.Warnf("Failed to select Agent by ID for (%s, %s).", agentID, status)

		switch status {
		case inventorypb.AgentStatus_STOPPING, inventorypb.AgentStatus_DONE:
			return nil
		}
	}

	if err != nil {
		return errors.Wrap(err, "failed to select Agent by ID")
	}

	agent.Status = status.String()
	agent.ListenPort = pointer.ToUint16(uint16(listenPort))
	if err = q.Update(agent); err != nil {
		return errors.Wrap(err, "failed to update Agent")
	}
	return nil
}

func (r *Registry) stateChanged(ctx context.Context, req *agentpb.StateChangedRequest) error {
	e := r.db.InTransaction(func(tx *reform.TX) error {
		agentIDs := r.roster.get(req.AgentId)
		if agentIDs == nil {
			agentIDs = []string{req.AgentId}
		}

		for _, agentID := range agentIDs {
			if err := updateAgentStatus(ctx, tx.Querier, agentID, req.Status, req.ListenPort); err != nil {
				return err
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	r.prometheus.RequestConfigurationUpdate()
	r.vmdb.RequestConfigurationUpdate()
	return nil
}

// SendSetStateRequest sends SetStateRequest to pmm-agent with given ID.
func (r *Registry) SendSetStateRequest(ctx context.Context, pmmAgentID string) {
	l := logger.Get(ctx)
	start := time.Now()
	defer func() {
		if dur := time.Since(start); dur > time.Second {
			l.Warnf("SendSetStateRequest took %s.", dur)
		}
	}()

	agent, err := r.get(pmmAgentID)
	if err != nil {
		l.Infof("SendSetStateRequest: %s.", err)
		return
	}

	pmmAgent, err := models.FindAgentByID(r.db.Querier, pmmAgentID)
	if err != nil {
		l.Errorf("Failed to get PMM Agent: %s.", err)
		return
	}
	pmmAgentVersion, err := version.Parse(*pmmAgent.Version)
	if err != nil {
		l.Errorf("Failed to parse PMM agent version %q: %s", *pmmAgent.Version, err)
		return
	}

	agents, err := models.FindAgents(r.db.Querier, models.AgentFilters{PMMAgentID: pmmAgentID})
	if err != nil {
		l.Errorf("Failed to collect agents: %s.", err)
		return
	}

	redactMode := redactSecrets
	if l.Logger.GetLevel() >= logrus.DebugLevel {
		redactMode = exposeSecrets
	}

	rdsExporters := make(map[*models.Node]*models.Agent)
	agentProcesses := make(map[string]*agentpb.SetStateRequest_AgentProcess)
	builtinAgents := make(map[string]*agentpb.SetStateRequest_BuiltinAgent)
	for _, row := range agents {
		if row.Disabled {
			continue
		}

		// in order of AgentType consts
		switch row.AgentType {
		case models.PMMAgentType:
			continue

		case models.NodeExporterType:
			node, err := models.FindNodeByID(r.db.Querier, pointer.GetString(row.NodeID))
			if err != nil {
				l.Error(err)
				return
			}
			agentProcesses[row.AgentID] = nodeExporterConfig(node, row)

		case models.RDSExporterType:
			node, err := models.FindNodeByID(r.db.Querier, pointer.GetString(row.NodeID))
			if err != nil {
				l.Error(err)
				return
			}
			rdsExporters[node] = row

		// Agents with exactly one Service
		case models.MySQLdExporterType, models.MongoDBExporterType, models.PostgresExporterType, models.ProxySQLExporterType,
			models.QANMySQLPerfSchemaAgentType, models.QANMySQLSlowlogAgentType, models.QANMongoDBProfilerAgentType, models.QANPostgreSQLPgStatementsAgentType,
			models.QANPostgreSQLPgStatMonitorAgentType:

			service, err := models.FindServiceByID(r.db.Querier, pointer.GetString(row.ServiceID))
			if err != nil {
				l.Error(err)
				return
			}

			switch row.AgentType {
			case models.MySQLdExporterType:
				agentProcesses[row.AgentID] = mysqldExporterConfig(service, row, redactMode)
			case models.MongoDBExporterType:
				agentProcesses[row.AgentID] = mongodbExporterConfig(service, row, redactMode, pmmAgentVersion)
			case models.PostgresExporterType:
				agentProcesses[row.AgentID] = postgresExporterConfig(service, row, redactMode)
			case models.ProxySQLExporterType:
				agentProcesses[row.AgentID] = proxysqlExporterConfig(service, row, redactMode)
			case models.QANMySQLPerfSchemaAgentType:
				builtinAgents[row.AgentID] = qanMySQLPerfSchemaAgentConfig(service, row)
			case models.QANMySQLSlowlogAgentType:
				builtinAgents[row.AgentID] = qanMySQLSlowlogAgentConfig(service, row)
			case models.QANMongoDBProfilerAgentType:
				builtinAgents[row.AgentID] = qanMongoDBProfilerAgentConfig(service, row)
			case models.QANPostgreSQLPgStatementsAgentType:
				builtinAgents[row.AgentID] = qanPostgreSQLPgStatementsAgentConfig(service, row)
			case models.QANPostgreSQLPgStatMonitorAgentType:
				builtinAgents[row.AgentID] = qanPostgreSQLPgStatMonitorAgentConfig(service, row)
			}

		case models.ExternalExporterType:
			// ignore

		default:
			l.Panicf("unhandled Agent type %s", row.AgentType)
		}
	}

	if len(rdsExporters) > 0 {
		rdsExporterIDs := make([]string, 0, len(rdsExporters))
		for _, rdsExporter := range rdsExporters {
			rdsExporterIDs = append(rdsExporterIDs, rdsExporter.AgentID)
		}
		sort.Strings(rdsExporterIDs)

		groupID := r.roster.add(pmmAgentID, rdsGroup, rdsExporterIDs)
		c, err := rdsExporterConfig(rdsExporters, redactMode)
		if err == nil {
			agentProcesses[groupID] = c
		} else {
			l.Errorf("%+v", err)
		}
	}

	state := &agentpb.SetStateRequest{
		AgentProcesses: agentProcesses,
		BuiltinAgents:  builtinAgents,
	}
	l.Infof("SendSetStateRequest: %+v.", state)
	resp := agent.channel.SendRequest(state)
	l.Infof("SetState response: %+v.", resp)
}

// CheckConnectionToService sends request to pmm-agent to check connection to service.
func (r *Registry) CheckConnectionToService(ctx context.Context, q *reform.Querier, service *models.Service, agent *models.Agent) error {
	// TODO: extract to a separate struct to keep Single Responsibility principles: https://jira.percona.com/browse/PMM-4932
	l := logger.Get(ctx)
	start := time.Now()
	defer func() {
		if dur := time.Since(start); dur > 4*time.Second {
			l.Warnf("CheckConnectionToService took %s.", dur)
		}
	}()

	pmmAgentID := pointer.GetString(agent.PMMAgentID)
	pmmAgent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	var request *agentpb.CheckConnectionRequest
	switch service.ServiceType {
	case models.MySQLServiceType:
		request = &agentpb.CheckConnectionRequest{
			Type:    inventorypb.ServiceType_MYSQL_SERVICE,
			Dsn:     agent.DSN(service, 2*time.Second, ""),
			Timeout: ptypes.DurationProto(3 * time.Second),
		}
	case models.PostgreSQLServiceType:
		request = &agentpb.CheckConnectionRequest{
			Type:    inventorypb.ServiceType_POSTGRESQL_SERVICE,
			Dsn:     agent.DSN(service, 2*time.Second, "postgres"),
			Timeout: ptypes.DurationProto(3 * time.Second),
		}
	case models.MongoDBServiceType:
		request = &agentpb.CheckConnectionRequest{
			Type:    inventorypb.ServiceType_MONGODB_SERVICE,
			Dsn:     agent.DSN(service, 2*time.Second, ""),
			Timeout: ptypes.DurationProto(3 * time.Second),
		}
	case models.ProxySQLServiceType:
		request = &agentpb.CheckConnectionRequest{
			Type:    inventorypb.ServiceType_PROXYSQL_SERVICE,
			Dsn:     agent.DSN(service, 2*time.Second, ""),
			Timeout: ptypes.DurationProto(3 * time.Second),
		}
	default:
		l.Panicf("unhandled Service type %s", service.ServiceType)
	}

	l.Infof("CheckConnectionRequest: %+v.", request)
	resp := pmmAgent.channel.SendRequest(request)
	l.Infof("CheckConnection response: %+v.", resp)

	switch service.ServiceType {
	case models.MySQLServiceType:
		tableCount := resp.(*agentpb.CheckConnectionResponse).GetStats().GetTableCount()
		agent.TableCount = &tableCount
		l.Debugf("Updating table count: %d.", tableCount)
		if err = q.Update(agent); err != nil {
			return errors.Wrap(err, "failed to update table count")
		}

	case models.PostgreSQLServiceType:
	case models.MongoDBServiceType:
	case models.ProxySQLServiceType:
		// nothing yet

	default:
		l.Panicf("unhandled Service type %s", service.ServiceType)
	}

	msg := resp.(*agentpb.CheckConnectionResponse).Error
	switch msg {
	case "":
		return nil
	case context.Canceled.Error(), context.DeadlineExceeded.Error():
		msg = fmt.Sprintf("timeout (%s)", msg)
	}
	return status.Error(codes.FailedPrecondition, fmt.Sprintf("Connection check failed: %s.", msg))
}

func (r *Registry) get(pmmAgentID string) (*pmmAgentInfo, error) {
	r.rw.RLock()
	pmmAgent := r.agents[pmmAgentID]
	r.rw.RUnlock()
	if pmmAgent == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "pmm-agent with ID %q is not currently connected", pmmAgentID)
	}
	return pmmAgent, nil
}

// Describe implements prometheus.Collector.
func (r *Registry) Describe(ch chan<- *prom.Desc) {
	r.sharedMetrics.Describe(ch)
	r.mConnects.Describe(ch)
	r.mDisconnects.Describe(ch)
	r.mRoundTrip.Describe(ch)
	r.mClockDrift.Describe(ch)
}

// Collect implement prometheus.Collector.
func (r *Registry) Collect(ch chan<- prom.Metric) {
	r.sharedMetrics.Collect(ch)
	r.mConnects.Collect(ch)
	r.mDisconnects.Collect(ch)
	r.mRoundTrip.Collect(ch)
	r.mClockDrift.Collect(ch)
}

// StartMySQLExplainAction starts MySQL EXPLAIN Action on pmm-agent.
// TODO: Extract it from here: https://jira.percona.com/browse/PMM-4932
func (r *Registry) StartMySQLExplainAction(ctx context.Context, id, pmmAgentID, dsn, query string, format agentpb.MysqlExplainOutputFormat) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_MysqlExplainParams{
			MysqlExplainParams: &agentpb.StartActionRequest_MySQLExplainParams{
				Dsn:          dsn,
				Query:        query,
				OutputFormat: format,
			},
		},
		Timeout: defaultActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartMySQLShowCreateTableAction starts mysql-show-create-table action on pmm-agent.
// TODO: Extract it from here: https://jira.percona.com/browse/PMM-4932
func (r *Registry) StartMySQLShowCreateTableAction(ctx context.Context, id, pmmAgentID, dsn, table string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_MysqlShowCreateTableParams{
			MysqlShowCreateTableParams: &agentpb.StartActionRequest_MySQLShowCreateTableParams{
				Dsn:   dsn,
				Table: table,
			},
		},
		Timeout: defaultActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartMySQLShowTableStatusAction starts mysql-show-table-status action on pmm-agent.
// TODO: Extract it from here: https://jira.percona.com/browse/PMM-4932
func (r *Registry) StartMySQLShowTableStatusAction(ctx context.Context, id, pmmAgentID, dsn, table string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_MysqlShowTableStatusParams{
			MysqlShowTableStatusParams: &agentpb.StartActionRequest_MySQLShowTableStatusParams{
				Dsn:   dsn,
				Table: table,
			},
		},
		Timeout: defaultActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartMySQLShowIndexAction starts mysql-show-index action on pmm-agent.
// TODO: Extract it from here: https://jira.percona.com/browse/PMM-4932
func (r *Registry) StartMySQLShowIndexAction(ctx context.Context, id, pmmAgentID, dsn, table string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_MysqlShowIndexParams{
			MysqlShowIndexParams: &agentpb.StartActionRequest_MySQLShowIndexParams{
				Dsn:   dsn,
				Table: table,
			},
		},
		Timeout: defaultActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartPostgreSQLShowCreateTableAction starts postgresql-show-create-table action on pmm-agent.
// TODO: Extract it from here: https://jira.percona.com/browse/PMM-4932
func (r *Registry) StartPostgreSQLShowCreateTableAction(ctx context.Context, id, pmmAgentID, dsn, table string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_PostgresqlShowCreateTableParams{
			PostgresqlShowCreateTableParams: &agentpb.StartActionRequest_PostgreSQLShowCreateTableParams{
				Dsn:   dsn,
				Table: table,
			},
		},
		Timeout: defaultActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartPostgreSQLShowIndexAction starts postgresql-show-index action on pmm-agent.
// TODO: Extract it from here: https://jira.percona.com/browse/PMM-4932
func (r *Registry) StartPostgreSQLShowIndexAction(ctx context.Context, id, pmmAgentID, dsn, table string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_PostgresqlShowIndexParams{
			PostgresqlShowIndexParams: &agentpb.StartActionRequest_PostgreSQLShowIndexParams{
				Dsn:   dsn,
				Table: table,
			},
		},
		Timeout: defaultActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartMongoDBExplainAction starts MongoDB query explain action on pmm-agent.
func (r *Registry) StartMongoDBExplainAction(ctx context.Context, id, pmmAgentID, dsn, query string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_MongodbExplainParams{
			MongodbExplainParams: &agentpb.StartActionRequest_MongoDBExplainParams{
				Dsn:   dsn,
				Query: query,
			},
		},
		Timeout: defaultActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartMySQLQueryShowAction starts MySQL SHOW query action on pmm-agent.
func (r *Registry) StartMySQLQueryShowAction(ctx context.Context, id, pmmAgentID, dsn, query string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_MysqlQueryShowParams{
			MysqlQueryShowParams: &agentpb.StartActionRequest_MySQLQueryShowParams{
				Dsn:   dsn,
				Query: query,
			},
		},
		Timeout: defaultQueryActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartMySQLQuerySelectAction starts MySQL SELECT query action on pmm-agent.
func (r *Registry) StartMySQLQuerySelectAction(ctx context.Context, id, pmmAgentID, dsn, query string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_MysqlQuerySelectParams{
			MysqlQuerySelectParams: &agentpb.StartActionRequest_MySQLQuerySelectParams{
				Dsn:   dsn,
				Query: query,
			},
		},
		Timeout: defaultQueryActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartPostgreSQLQueryShowAction starts PostgreSQL SHOW query action on pmm-agent.
func (r *Registry) StartPostgreSQLQueryShowAction(ctx context.Context, id, pmmAgentID, dsn string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_PostgresqlQueryShowParams{
			PostgresqlQueryShowParams: &agentpb.StartActionRequest_PostgreSQLQueryShowParams{
				Dsn: dsn,
			},
		},
		Timeout: defaultQueryActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartPostgreSQLQuerySelectAction starts PostgreSQL SELECT query action on pmm-agent.
func (r *Registry) StartPostgreSQLQuerySelectAction(ctx context.Context, id, pmmAgentID, dsn, query string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_PostgresqlQuerySelectParams{
			PostgresqlQuerySelectParams: &agentpb.StartActionRequest_PostgreSQLQuerySelectParams{
				Dsn:   dsn,
				Query: query,
			},
		},
		Timeout: defaultQueryActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartMongoDBQueryGetParameterAction starts MongoDB getParameter query action on pmm-agent.
func (r *Registry) StartMongoDBQueryGetParameterAction(ctx context.Context, id, pmmAgentID, dsn string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_MongodbQueryGetparameterParams{
			MongodbQueryGetparameterParams: &agentpb.StartActionRequest_MongoDBQueryGetParameterParams{
				Dsn: dsn,
			},
		},
		Timeout: defaultQueryActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartMongoDBQueryBuildInfoAction starts MongoDB buildInfo query action on pmm-agent.
func (r *Registry) StartMongoDBQueryBuildInfoAction(ctx context.Context, id, pmmAgentID, dsn string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_MongodbQueryBuildinfoParams{
			MongodbQueryBuildinfoParams: &agentpb.StartActionRequest_MongoDBQueryBuildInfoParams{
				Dsn: dsn,
			},
		},
		Timeout: defaultQueryActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartMongoDBQueryGetCmdLineOptsAction starts MongoDB getCmdLineOpts query action on pmm-agent.
func (r *Registry) StartMongoDBQueryGetCmdLineOptsAction(ctx context.Context, id, pmmAgentID, dsn string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		Params: &agentpb.StartActionRequest_MongodbQueryGetcmdlineoptsParams{
			MongodbQueryGetcmdlineoptsParams: &agentpb.StartActionRequest_MongoDBQueryGetCmdLineOptsParams{
				Dsn: dsn,
			},
		},
		Timeout: defaultQueryActionTimeout,
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartPTSummaryAction starts pt-summary action on pmm-agent.
func (r *Registry) StartPTSummaryAction(ctx context.Context, id, pmmAgentID string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		// Need pass params, even empty, because othervise request's marshal fail.
		Params: &agentpb.StartActionRequest_PtSummaryParams{
			PtSummaryParams: &agentpb.StartActionRequest_PTSummaryParams{},
		},
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StartPTMySqlSummaryAction starts pt-summary action on pmm-agent.
func (r *Registry) StartPTMySqlSummaryAction(ctx context.Context, id, pmmAgentID string) error {
	aRequest := &agentpb.StartActionRequest{
		ActionId: id,
		// Need pass params, even empty, because othervise request's marshal fail.
		Params: &agentpb.StartActionRequest_PtMySqlSummaryParams{
			PtMySqlSummaryParams: &agentpb.StartActionRequest_PTMySqlSummaryParams{},
		},
	}

	agent, err := r.get(pmmAgentID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(aRequest)
	return nil
}

// StopAction stops action with given given id.
// TODO: Extract it from here: https://jira.percona.com/browse/PMM-4932
func (r *Registry) StopAction(ctx context.Context, actionID string) error {
	agent, err := r.get(actionID)
	if err != nil {
		return err
	}

	agent.channel.SendRequest(&agentpb.StopActionRequest{ActionId: actionID})
	return nil
}

// check interfaces
var (
	_ prom.Collector = (*Registry)(nil)
)
