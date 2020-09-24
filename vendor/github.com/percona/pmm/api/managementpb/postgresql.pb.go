// Code generated by protoc-gen-go. DO NOT EDIT.
// source: managementpb/postgresql.proto

package managementpb

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	_ "github.com/mwitkow/go-proto-validators"
	inventorypb "github.com/percona/pmm/api/inventorypb"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type AddPostgreSQLRequest struct {
	// Node identifier on which a service is been running.
	// Exactly one of these parameters should be present: node_id, node_name, add_node.
	NodeId string `protobuf:"bytes,1,opt,name=node_id,json=nodeId,proto3" json:"node_id,omitempty"`
	// Node name on which a service is been running.
	// Exactly one of these parameters should be present: node_id, node_name, add_node.
	NodeName string `protobuf:"bytes,2,opt,name=node_name,json=nodeName,proto3" json:"node_name,omitempty"`
	// Create a new Node with those parameters.
	// Exactly one of these parameters should be present: node_id, node_name, add_node.
	AddNode *AddNodeParams `protobuf:"bytes,3,opt,name=add_node,json=addNode,proto3" json:"add_node,omitempty"`
	// Unique across all Services user-defined name. Required.
	ServiceName string `protobuf:"bytes,4,opt,name=service_name,json=serviceName,proto3" json:"service_name,omitempty"`
	// Node and Service access address (DNS name or IP).
	// Address (and port) or socket is required.
	Address string `protobuf:"bytes,5,opt,name=address,proto3" json:"address,omitempty"`
	// Service Access port.
	// Port is required when the address present.
	Port uint32 `protobuf:"varint,6,opt,name=port,proto3" json:"port,omitempty"`
	// Service Access socket.
	// Address (and port) or socket is required.
	Socket string `protobuf:"bytes,18,opt,name=socket,proto3" json:"socket,omitempty"`
	// The "pmm-agent" identifier which should run agents. Required.
	PmmAgentId string `protobuf:"bytes,7,opt,name=pmm_agent_id,json=pmmAgentId,proto3" json:"pmm_agent_id,omitempty"`
	// Environment name.
	Environment string `protobuf:"bytes,8,opt,name=environment,proto3" json:"environment,omitempty"`
	// Cluster name.
	Cluster string `protobuf:"bytes,9,opt,name=cluster,proto3" json:"cluster,omitempty"`
	// Replication set name.
	ReplicationSet string `protobuf:"bytes,10,opt,name=replication_set,json=replicationSet,proto3" json:"replication_set,omitempty"`
	// PostgreSQL username for scraping metrics.
	Username string `protobuf:"bytes,11,opt,name=username,proto3" json:"username,omitempty"`
	// PostgreSQL password for scraping metrics.
	Password string `protobuf:"bytes,12,opt,name=password,proto3" json:"password,omitempty"`
	// If true, adds qan-postgresql-pgstatements-agent for provided service.
	QanPostgresqlPgstatementsAgent bool `protobuf:"varint,13,opt,name=qan_postgresql_pgstatements_agent,json=qanPostgresqlPgstatementsAgent,proto3" json:"qan_postgresql_pgstatements_agent,omitempty"`
	// If true, adds qan-postgresql-pgstatmonitor-agent for provided service.
	QanPostgresqlPgstatmonitorAgent bool `protobuf:"varint,19,opt,name=qan_postgresql_pgstatmonitor_agent,json=qanPostgresqlPgstatmonitorAgent,proto3" json:"qan_postgresql_pgstatmonitor_agent,omitempty"`
	// Disable query examples.
	DisableQueryExamples bool `protobuf:"varint,20,opt,name=disable_query_examples,json=disableQueryExamples,proto3" json:"disable_query_examples,omitempty"`
	// Custom user-assigned labels for Service.
	CustomLabels map[string]string `protobuf:"bytes,14,rep,name=custom_labels,json=customLabels,proto3" json:"custom_labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// Skip connection check.
	SkipConnectionCheck bool `protobuf:"varint,15,opt,name=skip_connection_check,json=skipConnectionCheck,proto3" json:"skip_connection_check,omitempty"`
	// Use TLS for database connections.
	Tls bool `protobuf:"varint,16,opt,name=tls,proto3" json:"tls,omitempty"`
	// Skip TLS certificate and hostname validation. Uses sslmode=required instead of verify-full.
	TlsSkipVerify        bool     `protobuf:"varint,17,opt,name=tls_skip_verify,json=tlsSkipVerify,proto3" json:"tls_skip_verify,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AddPostgreSQLRequest) Reset()         { *m = AddPostgreSQLRequest{} }
func (m *AddPostgreSQLRequest) String() string { return proto.CompactTextString(m) }
func (*AddPostgreSQLRequest) ProtoMessage()    {}
func (*AddPostgreSQLRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_6e72a2ebc60b1270, []int{0}
}

func (m *AddPostgreSQLRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AddPostgreSQLRequest.Unmarshal(m, b)
}
func (m *AddPostgreSQLRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AddPostgreSQLRequest.Marshal(b, m, deterministic)
}
func (m *AddPostgreSQLRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AddPostgreSQLRequest.Merge(m, src)
}
func (m *AddPostgreSQLRequest) XXX_Size() int {
	return xxx_messageInfo_AddPostgreSQLRequest.Size(m)
}
func (m *AddPostgreSQLRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AddPostgreSQLRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AddPostgreSQLRequest proto.InternalMessageInfo

func (m *AddPostgreSQLRequest) GetNodeId() string {
	if m != nil {
		return m.NodeId
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetNodeName() string {
	if m != nil {
		return m.NodeName
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetAddNode() *AddNodeParams {
	if m != nil {
		return m.AddNode
	}
	return nil
}

func (m *AddPostgreSQLRequest) GetServiceName() string {
	if m != nil {
		return m.ServiceName
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *AddPostgreSQLRequest) GetSocket() string {
	if m != nil {
		return m.Socket
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetPmmAgentId() string {
	if m != nil {
		return m.PmmAgentId
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetEnvironment() string {
	if m != nil {
		return m.Environment
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetCluster() string {
	if m != nil {
		return m.Cluster
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetReplicationSet() string {
	if m != nil {
		return m.ReplicationSet
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func (m *AddPostgreSQLRequest) GetQanPostgresqlPgstatementsAgent() bool {
	if m != nil {
		return m.QanPostgresqlPgstatementsAgent
	}
	return false
}

func (m *AddPostgreSQLRequest) GetQanPostgresqlPgstatmonitorAgent() bool {
	if m != nil {
		return m.QanPostgresqlPgstatmonitorAgent
	}
	return false
}

func (m *AddPostgreSQLRequest) GetDisableQueryExamples() bool {
	if m != nil {
		return m.DisableQueryExamples
	}
	return false
}

func (m *AddPostgreSQLRequest) GetCustomLabels() map[string]string {
	if m != nil {
		return m.CustomLabels
	}
	return nil
}

func (m *AddPostgreSQLRequest) GetSkipConnectionCheck() bool {
	if m != nil {
		return m.SkipConnectionCheck
	}
	return false
}

func (m *AddPostgreSQLRequest) GetTls() bool {
	if m != nil {
		return m.Tls
	}
	return false
}

func (m *AddPostgreSQLRequest) GetTlsSkipVerify() bool {
	if m != nil {
		return m.TlsSkipVerify
	}
	return false
}

type AddPostgreSQLResponse struct {
	Service                         *inventorypb.PostgreSQLService               `protobuf:"bytes,1,opt,name=service,proto3" json:"service,omitempty"`
	PostgresExporter                *inventorypb.PostgresExporter                `protobuf:"bytes,2,opt,name=postgres_exporter,json=postgresExporter,proto3" json:"postgres_exporter,omitempty"`
	QanPostgresqlPgstatementsAgent  *inventorypb.QANPostgreSQLPgStatementsAgent  `protobuf:"bytes,3,opt,name=qan_postgresql_pgstatements_agent,json=qanPostgresqlPgstatementsAgent,proto3" json:"qan_postgresql_pgstatements_agent,omitempty"`
	QanPostgresqlPgstatmonitorAgent *inventorypb.QANPostgreSQLPgStatMonitorAgent `protobuf:"bytes,4,opt,name=qan_postgresql_pgstatmonitor_agent,json=qanPostgresqlPgstatmonitorAgent,proto3" json:"qan_postgresql_pgstatmonitor_agent,omitempty"`
	XXX_NoUnkeyedLiteral            struct{}                                     `json:"-"`
	XXX_unrecognized                []byte                                       `json:"-"`
	XXX_sizecache                   int32                                        `json:"-"`
}

func (m *AddPostgreSQLResponse) Reset()         { *m = AddPostgreSQLResponse{} }
func (m *AddPostgreSQLResponse) String() string { return proto.CompactTextString(m) }
func (*AddPostgreSQLResponse) ProtoMessage()    {}
func (*AddPostgreSQLResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_6e72a2ebc60b1270, []int{1}
}

func (m *AddPostgreSQLResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AddPostgreSQLResponse.Unmarshal(m, b)
}
func (m *AddPostgreSQLResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AddPostgreSQLResponse.Marshal(b, m, deterministic)
}
func (m *AddPostgreSQLResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AddPostgreSQLResponse.Merge(m, src)
}
func (m *AddPostgreSQLResponse) XXX_Size() int {
	return xxx_messageInfo_AddPostgreSQLResponse.Size(m)
}
func (m *AddPostgreSQLResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_AddPostgreSQLResponse.DiscardUnknown(m)
}

var xxx_messageInfo_AddPostgreSQLResponse proto.InternalMessageInfo

func (m *AddPostgreSQLResponse) GetService() *inventorypb.PostgreSQLService {
	if m != nil {
		return m.Service
	}
	return nil
}

func (m *AddPostgreSQLResponse) GetPostgresExporter() *inventorypb.PostgresExporter {
	if m != nil {
		return m.PostgresExporter
	}
	return nil
}

func (m *AddPostgreSQLResponse) GetQanPostgresqlPgstatementsAgent() *inventorypb.QANPostgreSQLPgStatementsAgent {
	if m != nil {
		return m.QanPostgresqlPgstatementsAgent
	}
	return nil
}

func (m *AddPostgreSQLResponse) GetQanPostgresqlPgstatmonitorAgent() *inventorypb.QANPostgreSQLPgStatMonitorAgent {
	if m != nil {
		return m.QanPostgresqlPgstatmonitorAgent
	}
	return nil
}

func init() {
	proto.RegisterType((*AddPostgreSQLRequest)(nil), "management.AddPostgreSQLRequest")
	proto.RegisterMapType((map[string]string)(nil), "management.AddPostgreSQLRequest.CustomLabelsEntry")
	proto.RegisterType((*AddPostgreSQLResponse)(nil), "management.AddPostgreSQLResponse")
}

func init() {
	proto.RegisterFile("managementpb/postgresql.proto", fileDescriptor_6e72a2ebc60b1270)
}

var fileDescriptor_6e72a2ebc60b1270 = []byte{
	// 809 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x54, 0x4d, 0x6f, 0x1b, 0x37,
	0x10, 0xc5, 0xda, 0x8e, 0x24, 0x8f, 0x24, 0x7f, 0x30, 0x4e, 0xca, 0x2a, 0x49, 0xa3, 0xe8, 0xd0,
	0x2a, 0x01, 0xa2, 0x45, 0xd5, 0x20, 0x28, 0x72, 0x29, 0x14, 0xc3, 0x40, 0x8d, 0xa6, 0x86, 0xbc,
	0x02, 0xda, 0xa2, 0x97, 0x05, 0xb5, 0x3b, 0xdd, 0x2c, 0xb4, 0x4b, 0x52, 0x24, 0x25, 0x47, 0x97,
	0x1e, 0x7a, 0xea, 0xa1, 0xb7, 0x5e, 0xfa, 0xbf, 0xfa, 0x03, 0x0a, 0x14, 0xfd, 0x21, 0x05, 0xb9,
	0xab, 0x2f, 0x3b, 0x88, 0x73, 0xe3, 0xcc, 0x7b, 0x7c, 0x33, 0x43, 0x3e, 0x12, 0x1e, 0xe5, 0x8c,
	0xb3, 0x04, 0x73, 0xe4, 0x46, 0x8e, 0x7d, 0x29, 0xb4, 0x49, 0x14, 0xea, 0x69, 0xd6, 0x93, 0x4a,
	0x18, 0x41, 0x60, 0x0d, 0xb7, 0x5e, 0x26, 0xa9, 0x79, 0x3b, 0x1b, 0xf7, 0x22, 0x91, 0xfb, 0xf9,
	0x55, 0x6a, 0x26, 0xe2, 0xca, 0x4f, 0xc4, 0x73, 0x47, 0x7c, 0x3e, 0x67, 0x59, 0x1a, 0x33, 0x23,
	0x94, 0xf6, 0x57, 0xcb, 0x42, 0xa3, 0xf5, 0x30, 0x11, 0x22, 0xc9, 0xd0, 0x67, 0x32, 0xf5, 0x19,
	0xe7, 0xc2, 0x30, 0x93, 0x0a, 0xae, 0x4b, 0x94, 0xa6, 0x7c, 0x8e, 0xdc, 0x08, 0xb5, 0x90, 0x63,
	0x9f, 0x25, 0xc8, 0xcd, 0x12, 0x69, 0x6d, 0x22, 0x1a, 0xd5, 0x3c, 0x8d, 0x70, 0x85, 0x6d, 0xb5,
	0x5d, 0x82, 0x05, 0xd6, 0xf9, 0xab, 0x0a, 0x27, 0x83, 0x38, 0x1e, 0x16, 0xb3, 0x8c, 0x2e, 0xdf,
	0x04, 0x38, 0x9d, 0xa1, 0x36, 0xe4, 0x13, 0xa8, 0x72, 0x11, 0x63, 0x98, 0xc6, 0xd4, 0x6b, 0x7b,
	0xdd, 0xfd, 0xa0, 0x62, 0xc3, 0xf3, 0x98, 0x3c, 0x80, 0x7d, 0x07, 0x70, 0x96, 0x23, 0xdd, 0x71,
	0x50, 0xcd, 0x26, 0x2e, 0x58, 0x8e, 0xe4, 0x05, 0xd4, 0x58, 0x1c, 0x87, 0x36, 0xa6, 0xbb, 0x6d,
	0xaf, 0x5b, 0xef, 0x7f, 0xda, 0x5b, 0x57, 0xef, 0x0d, 0xe2, 0xf8, 0x42, 0xc4, 0x38, 0x64, 0x8a,
	0xe5, 0x3a, 0xa8, 0xb2, 0x22, 0x24, 0x4f, 0xa1, 0x51, 0x76, 0x55, 0xa8, 0xee, 0x59, 0xd5, 0xd7,
	0x95, 0x7f, 0xff, 0x79, 0xbc, 0xf3, 0x93, 0x17, 0xd4, 0x4b, 0xcc, 0x15, 0xa0, 0x60, 0x77, 0x29,
	0xd4, 0x9a, 0xde, 0x71, 0xb5, 0x97, 0x21, 0x21, 0xb0, 0x27, 0x85, 0x32, 0xb4, 0xd2, 0xf6, 0xba,
	0xcd, 0xc0, 0xad, 0xc9, 0x7d, 0xa8, 0x68, 0x11, 0x4d, 0xd0, 0x50, 0x52, 0xcc, 0x50, 0x44, 0xa4,
	0x0b, 0x0d, 0x99, 0xe7, 0xa1, 0x3b, 0x41, 0x3b, 0x61, 0x75, 0xab, 0x20, 0xc8, 0x3c, 0x1f, 0x58,
	0xe8, 0x3c, 0x26, 0x6d, 0xa8, 0x23, 0x9f, 0xa7, 0x4a, 0x70, 0x3b, 0x00, 0xad, 0x39, 0x99, 0xcd,
	0x94, 0xed, 0x28, 0xca, 0x66, 0xda, 0xa0, 0xa2, 0xfb, 0x45, 0x47, 0x65, 0x48, 0xbe, 0x80, 0x43,
	0x85, 0x32, 0x4b, 0x23, 0x77, 0x87, 0xa1, 0x46, 0x43, 0xc1, 0x31, 0x0e, 0x36, 0xd2, 0x23, 0x34,
	0xa4, 0x03, 0xb5, 0x99, 0x46, 0xe5, 0x66, 0xaf, 0x6f, 0xb5, 0xb2, 0xca, 0x93, 0x16, 0xd4, 0x24,
	0xd3, 0xfa, 0x4a, 0xa8, 0x98, 0x36, 0x8a, 0x53, 0x5f, 0xc6, 0xe4, 0x1c, 0x9e, 0x4c, 0x19, 0x0f,
	0xd7, 0x86, 0x0c, 0x65, 0xa2, 0x0d, 0x33, 0xee, 0xd0, 0x75, 0x31, 0x26, 0x6d, 0xb6, 0xbd, 0x6e,
	0x2d, 0xf8, 0x6c, 0xca, 0xf8, 0x70, 0xc5, 0x1b, 0x6e, 0xd0, 0xdc, 0xc4, 0xe4, 0x3b, 0xe8, 0xbc,
	0x57, 0x2a, 0x17, 0x3c, 0x35, 0x42, 0x95, 0x5a, 0x77, 0x9d, 0xd6, 0xe3, 0xf7, 0x68, 0x95, 0xbc,
	0x42, 0xec, 0x05, 0xdc, 0x8f, 0x53, 0xcd, 0xc6, 0x19, 0x86, 0xd3, 0x19, 0xaa, 0x45, 0x88, 0xef,
	0x58, 0x2e, 0x33, 0xd4, 0xf4, 0xc4, 0x09, 0x9c, 0x94, 0xe8, 0xa5, 0x05, 0xcf, 0x4a, 0x8c, 0xfc,
	0x08, 0xcd, 0x68, 0xa6, 0x8d, 0xc8, 0xc3, 0x8c, 0x8d, 0x31, 0xd3, 0xf4, 0xa0, 0xbd, 0xdb, 0xad,
	0xf7, 0xfb, 0xd7, 0x8c, 0x74, 0xc3, 0xb2, 0xbd, 0x53, 0xb7, 0xeb, 0x8d, 0xdb, 0x74, 0xc6, 0x8d,
	0x5a, 0x04, 0x8d, 0x68, 0x23, 0x45, 0xfa, 0x70, 0x4f, 0x4f, 0x52, 0x19, 0x46, 0x82, 0x73, 0x8c,
	0xdc, 0x9d, 0x44, 0x6f, 0x31, 0x9a, 0xd0, 0x43, 0xd7, 0xcd, 0x5d, 0x0b, 0x9e, 0xae, 0xb0, 0x53,
	0x0b, 0x91, 0x23, 0xd8, 0x35, 0x99, 0xa6, 0x47, 0x8e, 0x61, 0x97, 0xe4, 0x73, 0x38, 0x34, 0x99,
	0x0e, 0x9d, 0xd2, 0x1c, 0x55, 0xfa, 0xcb, 0x82, 0x1e, 0x3b, 0xb4, 0x69, 0x32, 0x3d, 0x9a, 0xa4,
	0xf2, 0x07, 0x97, 0x6c, 0x7d, 0x03, 0xc7, 0x37, 0x1a, 0xb2, 0x72, 0x13, 0x5c, 0x94, 0x2f, 0xca,
	0x2e, 0xc9, 0x09, 0xdc, 0x99, 0xb3, 0x6c, 0xb6, 0x7c, 0x4a, 0x45, 0xf0, 0x6a, 0xe7, 0x6b, 0xaf,
	0xf3, 0xfb, 0x2e, 0xdc, 0xbb, 0x36, 0xa7, 0x96, 0x82, 0x6b, 0x24, 0x2f, 0xa1, 0x5a, 0xbe, 0x09,
	0xa7, 0x54, 0xef, 0x3f, 0xec, 0xad, 0x9e, 0x7f, 0x6f, 0xcd, 0x1f, 0x15, 0x9c, 0x60, 0x49, 0x26,
	0xdf, 0xc2, 0xf1, 0xf2, 0x62, 0x43, 0x7c, 0x67, 0x5f, 0x08, 0x2a, 0x57, 0xb7, 0xde, 0x7f, 0x70,
	0x53, 0x41, 0x9f, 0x95, 0x94, 0xe0, 0x48, 0x5e, 0xcb, 0x10, 0xf3, 0x31, 0x8e, 0x2b, 0x3e, 0x80,
	0xa7, 0x1b, 0xca, 0x97, 0x83, 0x8b, 0x75, 0x7b, 0xc3, 0x64, 0xb4, 0x6d, 0xbe, 0x5b, 0xcd, 0x79,
	0xf5, 0x51, 0xe6, 0xdc, 0x73, 0x65, 0x9f, 0x7d, 0xb8, 0xec, 0xf7, 0x1b, 0x3e, 0xbd, 0xd5, 0xc8,
	0xfd, 0x3f, 0x3c, 0x80, 0xb5, 0x02, 0xf9, 0x15, 0x9a, 0x5b, 0x17, 0x43, 0xda, 0xb7, 0x79, 0xb3,
	0xf5, 0xe4, 0x03, 0x8c, 0xe2, 0x56, 0x3b, 0xdd, 0xdf, 0xfe, 0xfe, 0xef, 0xcf, 0x9d, 0x4e, 0xe7,
	0x91, 0x3f, 0xff, 0xd2, 0x5f, 0xb3, 0xfd, 0x35, 0xd5, 0x1f, 0xc4, 0xf1, 0x2b, 0xef, 0xd9, 0xeb,
	0x83, 0x9f, 0x1b, 0x9b, 0x5f, 0xfa, 0xb8, 0xe2, 0xfe, 0xf2, 0xaf, 0xfe, 0x0f, 0x00, 0x00, 0xff,
	0xff, 0xd7, 0x29, 0x3b, 0xad, 0xa0, 0x06, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// PostgreSQLClient is the client API for PostgreSQL service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type PostgreSQLClient interface {
	// AddPostgreSQL adds PostgreSQL Service and starts postgres exporter.
	// It automatically adds a service to inventory, which is running on provided "node_id",
	// then adds "postgres_exporter" with provided "pmm_agent_id" and other parameters.
	AddPostgreSQL(ctx context.Context, in *AddPostgreSQLRequest, opts ...grpc.CallOption) (*AddPostgreSQLResponse, error)
}

type postgreSQLClient struct {
	cc grpc.ClientConnInterface
}

func NewPostgreSQLClient(cc grpc.ClientConnInterface) PostgreSQLClient {
	return &postgreSQLClient{cc}
}

func (c *postgreSQLClient) AddPostgreSQL(ctx context.Context, in *AddPostgreSQLRequest, opts ...grpc.CallOption) (*AddPostgreSQLResponse, error) {
	out := new(AddPostgreSQLResponse)
	err := c.cc.Invoke(ctx, "/management.PostgreSQL/AddPostgreSQL", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PostgreSQLServer is the server API for PostgreSQL service.
type PostgreSQLServer interface {
	// AddPostgreSQL adds PostgreSQL Service and starts postgres exporter.
	// It automatically adds a service to inventory, which is running on provided "node_id",
	// then adds "postgres_exporter" with provided "pmm_agent_id" and other parameters.
	AddPostgreSQL(context.Context, *AddPostgreSQLRequest) (*AddPostgreSQLResponse, error)
}

// UnimplementedPostgreSQLServer can be embedded to have forward compatible implementations.
type UnimplementedPostgreSQLServer struct {
}

func (*UnimplementedPostgreSQLServer) AddPostgreSQL(ctx context.Context, req *AddPostgreSQLRequest) (*AddPostgreSQLResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddPostgreSQL not implemented")
}

func RegisterPostgreSQLServer(s *grpc.Server, srv PostgreSQLServer) {
	s.RegisterService(&_PostgreSQL_serviceDesc, srv)
}

func _PostgreSQL_AddPostgreSQL_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddPostgreSQLRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PostgreSQLServer).AddPostgreSQL(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/management.PostgreSQL/AddPostgreSQL",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PostgreSQLServer).AddPostgreSQL(ctx, req.(*AddPostgreSQLRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _PostgreSQL_serviceDesc = grpc.ServiceDesc{
	ServiceName: "management.PostgreSQL",
	HandlerType: (*PostgreSQLServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AddPostgreSQL",
			Handler:    _PostgreSQL_AddPostgreSQL_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "managementpb/postgresql.proto",
}
