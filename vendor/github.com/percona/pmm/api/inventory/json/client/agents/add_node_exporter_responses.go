// Code generated by go-swagger; DO NOT EDIT.

package agents

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"

	strfmt "github.com/go-openapi/strfmt"
)

// AddNodeExporterReader is a Reader for the AddNodeExporter structure.
type AddNodeExporterReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AddNodeExporterReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {

	case 200:
		result := NewAddNodeExporterOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewAddNodeExporterOK creates a AddNodeExporterOK with default headers values
func NewAddNodeExporterOK() *AddNodeExporterOK {
	return &AddNodeExporterOK{}
}

/*AddNodeExporterOK handles this case with default header values.

(empty)
*/
type AddNodeExporterOK struct {
	Payload *AddNodeExporterOKBody
}

func (o *AddNodeExporterOK) Error() string {
	return fmt.Sprintf("[POST /v0/inventory/Agents/AddNodeExporter][%d] addNodeExporterOK  %+v", 200, o.Payload)
}

func (o *AddNodeExporterOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(AddNodeExporterOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*AddNodeExporterBody add node exporter body
swagger:model AddNodeExporterBody
*/
type AddNodeExporterBody struct {

	// Agent desired status: enabled or disabled.
	Disabled bool `json:"disabled,omitempty"`

	// host node info
	HostNodeInfo *AddNodeExporterParamsBodyHostNodeInfo `json:"host_node_info,omitempty"`
}

// Validate validates this add node exporter body
func (o *AddNodeExporterBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateHostNodeInfo(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *AddNodeExporterBody) validateHostNodeInfo(formats strfmt.Registry) error {

	if swag.IsZero(o.HostNodeInfo) { // not required
		return nil
	}

	if o.HostNodeInfo != nil {
		if err := o.HostNodeInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("body" + "." + "host_node_info")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *AddNodeExporterBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *AddNodeExporterBody) UnmarshalBinary(b []byte) error {
	var res AddNodeExporterBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*AddNodeExporterOKBody add node exporter o k body
swagger:model AddNodeExporterOKBody
*/
type AddNodeExporterOKBody struct {

	// node exporter
	NodeExporter *AddNodeExporterOKBodyNodeExporter `json:"node_exporter,omitempty"`
}

// Validate validates this add node exporter o k body
func (o *AddNodeExporterOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateNodeExporter(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *AddNodeExporterOKBody) validateNodeExporter(formats strfmt.Registry) error {

	if swag.IsZero(o.NodeExporter) { // not required
		return nil
	}

	if o.NodeExporter != nil {
		if err := o.NodeExporter.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("addNodeExporterOK" + "." + "node_exporter")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *AddNodeExporterOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *AddNodeExporterOKBody) UnmarshalBinary(b []byte) error {
	var res AddNodeExporterOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*AddNodeExporterOKBodyNodeExporter NodeExporter represents node_exporter Agent configuration.
swagger:model AddNodeExporterOKBodyNodeExporter
*/
type AddNodeExporterOKBodyNodeExporter struct {

	// Agent desired status: enabled or disabled.
	Disabled bool `json:"disabled,omitempty"`

	// host node info
	HostNodeInfo *AddNodeExporterOKBodyNodeExporterHostNodeInfo `json:"host_node_info,omitempty"`

	// Unique Agent identifier.
	ID string `json:"id,omitempty"`

	// HTTP listen port for exposing metrics.
	ListenPort int64 `json:"listen_port,omitempty"`

	// Agent process status: running or not.
	Running bool `json:"running,omitempty"`
}

// Validate validates this add node exporter o k body node exporter
func (o *AddNodeExporterOKBodyNodeExporter) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateHostNodeInfo(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *AddNodeExporterOKBodyNodeExporter) validateHostNodeInfo(formats strfmt.Registry) error {

	if swag.IsZero(o.HostNodeInfo) { // not required
		return nil
	}

	if o.HostNodeInfo != nil {
		if err := o.HostNodeInfo.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("addNodeExporterOK" + "." + "node_exporter" + "." + "host_node_info")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (o *AddNodeExporterOKBodyNodeExporter) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *AddNodeExporterOKBodyNodeExporter) UnmarshalBinary(b []byte) error {
	var res AddNodeExporterOKBodyNodeExporter
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*AddNodeExporterOKBodyNodeExporterHostNodeInfo HostNodeInfo describes the way Service or Agent runs on Node.
swagger:model AddNodeExporterOKBodyNodeExporterHostNodeInfo
*/
type AddNodeExporterOKBodyNodeExporterHostNodeInfo struct {

	// Docker container ID.
	ContainerID string `json:"container_id,omitempty"`

	// Docker container name.
	ContainerName string `json:"container_name,omitempty"`

	// Kubernetes pod name.
	KubernetesPodName string `json:"kubernetes_pod_name,omitempty"`

	// Kubernetes pod UID.
	KubernetesPodUID string `json:"kubernetes_pod_uid,omitempty"`

	// Node identifier where Service or Agent runs.
	NodeID string `json:"node_id,omitempty"`
}

// Validate validates this add node exporter o k body node exporter host node info
func (o *AddNodeExporterOKBodyNodeExporterHostNodeInfo) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *AddNodeExporterOKBodyNodeExporterHostNodeInfo) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *AddNodeExporterOKBodyNodeExporterHostNodeInfo) UnmarshalBinary(b []byte) error {
	var res AddNodeExporterOKBodyNodeExporterHostNodeInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

/*AddNodeExporterParamsBodyHostNodeInfo HostNodeInfo describes the way Service or Agent runs on Node.
swagger:model AddNodeExporterParamsBodyHostNodeInfo
*/
type AddNodeExporterParamsBodyHostNodeInfo struct {

	// Docker container ID.
	ContainerID string `json:"container_id,omitempty"`

	// Docker container name.
	ContainerName string `json:"container_name,omitempty"`

	// Kubernetes pod name.
	KubernetesPodName string `json:"kubernetes_pod_name,omitempty"`

	// Kubernetes pod UID.
	KubernetesPodUID string `json:"kubernetes_pod_uid,omitempty"`

	// Node identifier where Service or Agent runs.
	NodeID string `json:"node_id,omitempty"`
}

// Validate validates this add node exporter params body host node info
func (o *AddNodeExporterParamsBodyHostNodeInfo) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *AddNodeExporterParamsBodyHostNodeInfo) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *AddNodeExporterParamsBodyHostNodeInfo) UnmarshalBinary(b []byte) error {
	var res AddNodeExporterParamsBodyHostNodeInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}