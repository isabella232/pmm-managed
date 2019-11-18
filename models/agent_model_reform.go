// Code generated by gopkg.in/reform.v1. DO NOT EDIT.

package models

import (
	"fmt"
	"strings"

	"gopkg.in/reform.v1"
	"gopkg.in/reform.v1/parse"
)

type agentTableType struct {
	s parse.StructInfo
	z []interface{}
}

// Schema returns a schema name in SQL database ("").
func (v *agentTableType) Schema() string {
	return v.s.SQLSchema
}

// Name returns a view or table name in SQL database ("agents").
func (v *agentTableType) Name() string {
	return v.s.SQLName
}

// Columns returns a new slice of column names for that view or table in SQL database.
func (v *agentTableType) Columns() []string {
	return []string{"agent_id", "agent_type", "runs_on_node_id", "service_id", "node_id", "pmm_agent_id", "custom_labels", "created_at", "updated_at", "disabled", "status", "listen_port", "version", "username", "password", "tls", "tls_skip_verify", "table_count", "query_examples_disabled", "max_query_log_size", "metrics_url"}
}

// NewStruct makes a new struct for that view or table.
func (v *agentTableType) NewStruct() reform.Struct {
	return new(Agent)
}

// NewRecord makes a new record for that table.
func (v *agentTableType) NewRecord() reform.Record {
	return new(Agent)
}

// PKColumnIndex returns an index of primary key column for that table in SQL database.
func (v *agentTableType) PKColumnIndex() uint {
	return uint(v.s.PKFieldIndex)
}

// AgentTable represents agents view or table in SQL database.
var AgentTable = &agentTableType{
	s: parse.StructInfo{Type: "Agent", SQLSchema: "", SQLName: "agents", Fields: []parse.FieldInfo{{Name: "AgentID", Type: "string", Column: "agent_id"}, {Name: "AgentType", Type: "AgentType", Column: "agent_type"}, {Name: "RunsOnNodeID", Type: "*string", Column: "runs_on_node_id"}, {Name: "ServiceID", Type: "*string", Column: "service_id"}, {Name: "NodeID", Type: "*string", Column: "node_id"}, {Name: "PMMAgentID", Type: "*string", Column: "pmm_agent_id"}, {Name: "CustomLabels", Type: "[]uint8", Column: "custom_labels"}, {Name: "CreatedAt", Type: "time.Time", Column: "created_at"}, {Name: "UpdatedAt", Type: "time.Time", Column: "updated_at"}, {Name: "Disabled", Type: "bool", Column: "disabled"}, {Name: "Status", Type: "string", Column: "status"}, {Name: "ListenPort", Type: "*uint16", Column: "listen_port"}, {Name: "Version", Type: "*string", Column: "version"}, {Name: "Username", Type: "*string", Column: "username"}, {Name: "Password", Type: "*string", Column: "password"}, {Name: "TLS", Type: "bool", Column: "tls"}, {Name: "TLSSkipVerify", Type: "bool", Column: "tls_skip_verify"}, {Name: "TableCount", Type: "*int32", Column: "table_count"}, {Name: "QueryExamplesDisabled", Type: "bool", Column: "query_examples_disabled"}, {Name: "MaxQueryLogSize", Type: "int64", Column: "max_query_log_size"}, {Name: "MetricsURL", Type: "*string", Column: "metrics_url"}}, PKFieldIndex: 0},
	z: new(Agent).Values(),
}

// String returns a string representation of this struct or record.
func (s Agent) String() string {
	res := make([]string, 21)
	res[0] = "AgentID: " + reform.Inspect(s.AgentID, true)
	res[1] = "AgentType: " + reform.Inspect(s.AgentType, true)
	res[2] = "RunsOnNodeID: " + reform.Inspect(s.RunsOnNodeID, true)
	res[3] = "ServiceID: " + reform.Inspect(s.ServiceID, true)
	res[4] = "NodeID: " + reform.Inspect(s.NodeID, true)
	res[5] = "PMMAgentID: " + reform.Inspect(s.PMMAgentID, true)
	res[6] = "CustomLabels: " + reform.Inspect(s.CustomLabels, true)
	res[7] = "CreatedAt: " + reform.Inspect(s.CreatedAt, true)
	res[8] = "UpdatedAt: " + reform.Inspect(s.UpdatedAt, true)
	res[9] = "Disabled: " + reform.Inspect(s.Disabled, true)
	res[10] = "Status: " + reform.Inspect(s.Status, true)
	res[11] = "ListenPort: " + reform.Inspect(s.ListenPort, true)
	res[12] = "Version: " + reform.Inspect(s.Version, true)
	res[13] = "Username: " + reform.Inspect(s.Username, true)
	res[14] = "Password: " + reform.Inspect(s.Password, true)
	res[15] = "TLS: " + reform.Inspect(s.TLS, true)
	res[16] = "TLSSkipVerify: " + reform.Inspect(s.TLSSkipVerify, true)
	res[17] = "TableCount: " + reform.Inspect(s.TableCount, true)
	res[18] = "QueryExamplesDisabled: " + reform.Inspect(s.QueryExamplesDisabled, true)
	res[19] = "MaxQueryLogSize: " + reform.Inspect(s.MaxQueryLogSize, true)
	res[20] = "MetricsURL: " + reform.Inspect(s.MetricsURL, true)
	return strings.Join(res, ", ")
}

// Values returns a slice of struct or record field values.
// Returned interface{} values are never untyped nils.
func (s *Agent) Values() []interface{} {
	return []interface{}{
		s.AgentID,
		s.AgentType,
		s.RunsOnNodeID,
		s.ServiceID,
		s.NodeID,
		s.PMMAgentID,
		s.CustomLabels,
		s.CreatedAt,
		s.UpdatedAt,
		s.Disabled,
		s.Status,
		s.ListenPort,
		s.Version,
		s.Username,
		s.Password,
		s.TLS,
		s.TLSSkipVerify,
		s.TableCount,
		s.QueryExamplesDisabled,
		s.MaxQueryLogSize,
		s.MetricsURL,
	}
}

// Pointers returns a slice of pointers to struct or record fields.
// Returned interface{} values are never untyped nils.
func (s *Agent) Pointers() []interface{} {
	return []interface{}{
		&s.AgentID,
		&s.AgentType,
		&s.RunsOnNodeID,
		&s.ServiceID,
		&s.NodeID,
		&s.PMMAgentID,
		&s.CustomLabels,
		&s.CreatedAt,
		&s.UpdatedAt,
		&s.Disabled,
		&s.Status,
		&s.ListenPort,
		&s.Version,
		&s.Username,
		&s.Password,
		&s.TLS,
		&s.TLSSkipVerify,
		&s.TableCount,
		&s.QueryExamplesDisabled,
		&s.MaxQueryLogSize,
		&s.MetricsURL,
	}
}

// View returns View object for that struct.
func (s *Agent) View() reform.View {
	return AgentTable
}

// Table returns Table object for that record.
func (s *Agent) Table() reform.Table {
	return AgentTable
}

// PKValue returns a value of primary key for that record.
// Returned interface{} value is never untyped nil.
func (s *Agent) PKValue() interface{} {
	return s.AgentID
}

// PKPointer returns a pointer to primary key field for that record.
// Returned interface{} value is never untyped nil.
func (s *Agent) PKPointer() interface{} {
	return &s.AgentID
}

// HasPK returns true if record has non-zero primary key set, false otherwise.
func (s *Agent) HasPK() bool {
	return s.AgentID != AgentTable.z[AgentTable.s.PKFieldIndex]
}

// SetPK sets record primary key.
func (s *Agent) SetPK(pk interface{}) {
	if i64, ok := pk.(int64); ok {
		s.AgentID = string(i64)
	} else {
		s.AgentID = pk.(string)
	}
}

// check interfaces
var (
	_ reform.View   = AgentTable
	_ reform.Struct = (*Agent)(nil)
	_ reform.Table  = AgentTable
	_ reform.Record = (*Agent)(nil)
	_ fmt.Stringer  = (*Agent)(nil)
)

func init() {
	parse.AssertUpToDate(&AgentTable.s, new(Agent))
}
