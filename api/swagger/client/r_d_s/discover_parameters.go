// Code generated by go-swagger; DO NOT EDIT.

package r_d_s

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"
	"time"

	"golang.org/x/net/context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/percona/pmm-managed/api/swagger/models"
)

// NewDiscoverParams creates a new DiscoverParams object
// with the default values initialized.
func NewDiscoverParams() *DiscoverParams {
	var ()
	return &DiscoverParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewDiscoverParamsWithTimeout creates a new DiscoverParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewDiscoverParamsWithTimeout(timeout time.Duration) *DiscoverParams {
	var ()
	return &DiscoverParams{

		timeout: timeout,
	}
}

// NewDiscoverParamsWithContext creates a new DiscoverParams object
// with the default values initialized, and the ability to set a context for a request
func NewDiscoverParamsWithContext(ctx context.Context) *DiscoverParams {
	var ()
	return &DiscoverParams{

		Context: ctx,
	}
}

// NewDiscoverParamsWithHTTPClient creates a new DiscoverParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewDiscoverParamsWithHTTPClient(client *http.Client) *DiscoverParams {
	var ()
	return &DiscoverParams{
		HTTPClient: client,
	}
}

/*DiscoverParams contains all the parameters to send to the API endpoint
for the discover operation typically these are written to a http.Request
*/
type DiscoverParams struct {

	/*Body*/
	Body *models.APIRDSDiscoverRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the discover params
func (o *DiscoverParams) WithTimeout(timeout time.Duration) *DiscoverParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the discover params
func (o *DiscoverParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the discover params
func (o *DiscoverParams) WithContext(ctx context.Context) *DiscoverParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the discover params
func (o *DiscoverParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the discover params
func (o *DiscoverParams) WithHTTPClient(client *http.Client) *DiscoverParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the discover params
func (o *DiscoverParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the discover params
func (o *DiscoverParams) WithBody(body *models.APIRDSDiscoverRequest) *DiscoverParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the discover params
func (o *DiscoverParams) SetBody(body *models.APIRDSDiscoverRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *DiscoverParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}