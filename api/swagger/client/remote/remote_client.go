// Code generated by go-swagger; DO NOT EDIT.

package remote

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"
)

// New creates a new remote API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) *Client {
	return &Client{transport: transport, formats: formats}
}

/*
Client for remote API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

/*
ListMixin6 list mixin6 API
*/
func (a *Client) ListMixin6(params *ListMixin6Params) (*ListMixin6OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListMixin6Params()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "ListMixin6",
		Method:             "GET",
		PathPattern:        "/v0/remote",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &ListMixin6Reader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	return result.(*ListMixin6OK), nil

}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
