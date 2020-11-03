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

package management

import (
	"context"
	"strings"

	"github.com/percona-platform/saas/pkg/check"
	saasStarlark "github.com/percona-platform/saas/pkg/starlark"
	"github.com/percona/pmm/api/managementpb"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.starlark.net/starlark"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/percona/pmm-managed/services"
	"github.com/percona/pmm-managed/services/checks"
)

// ChecksAPIService represents security checks service API.
type ChecksAPIService struct {
	checksService checksService
	l             *logrus.Entry
}

// NewChecksAPIService creates new Checks API Service.
func NewChecksAPIService(checksService checksService) *ChecksAPIService {
	return &ChecksAPIService{
		checksService: checksService,
		l:             logrus.WithField("component", "management/checks"),
	}
}

// GetSecurityCheckResults returns Security Thread Tool's latest checks results.
func (s *ChecksAPIService) GetSecurityCheckResults() (*managementpb.GetSecurityCheckResultsResponse, error) {
	results, err := s.checksService.GetSecurityCheckResults()
	if err != nil {
		if err == services.ErrSTTDisabled {
			return nil, status.Errorf(codes.FailedPrecondition, "%v.", err)
		}

		return nil, errors.Wrap(err, "failed to get security check results")
	}

	checkResults := make([]*managementpb.SecurityCheckResult, 0, len(results))
	for _, result := range results {
		checkResults = append(checkResults, &managementpb.SecurityCheckResult{
			Summary:     result.Summary,
			Description: result.Description,
			Severity:    managementpb.Severity(result.Severity),
			Labels:      result.Labels,
		})
	}

	return &managementpb.GetSecurityCheckResultsResponse{Results: checkResults}, nil
}

// StartSecurityChecks executes Security Thread Tool checks and returns when all checks are executed.
func (s *ChecksAPIService) StartSecurityChecks(ctx context.Context) (*managementpb.StartSecurityChecksResponse, error) {
	err := s.checksService.StartChecks(ctx)
	if err != nil {
		if err == services.ErrSTTDisabled {
			return nil, status.Errorf(codes.FailedPrecondition, "%v.", err)
		}

		return nil, errors.Wrap(err, "failed to start security checks")
	}

	return &managementpb.StartSecurityChecksResponse{}, nil
}

// ListSecurityChecks returns a list of available Security Thread Tool checks and their statuses.
func (s *ChecksAPIService) ListSecurityChecks() (*managementpb.ListSecurityChecksResponse, error) {
	disChecks, err := s.checksService.GetDisabledChecks()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get disabled checks list")
	}

	m := make(map[string]struct{}, len(disChecks))
	for _, c := range disChecks {
		m[c] = struct{}{}
	}

	checks := s.checksService.GetAllChecks()
	res := make([]*managementpb.SecurityCheck, 0, len(checks))
	for _, c := range checks {
		_, disabled := m[c.Name]
		desc := s.getCheckDescription(c)
		res = append(res, &managementpb.SecurityCheck{Name: c.Name, Disabled: disabled, Description: desc})
	}

	return &managementpb.ListSecurityChecksResponse{Checks: res}, nil
}

// ChangeSecurityChecks enables/disables Security Thread Tool checks by names.
func (s *ChecksAPIService) ChangeSecurityChecks(req *managementpb.ChangeSecurityChecksRequest) (*managementpb.ChangeSecurityChecksResponse, error) {
	var enableChecks, disableChecks []string
	for _, check := range req.Params {
		if check.Enable && check.Disable {
			return nil, status.Errorf(codes.InvalidArgument, "Check %s has enable and disable parameters set to the true.", check.Name)
		}

		if check.Enable {
			enableChecks = append(enableChecks, check.Name)
		}

		if check.Disable {
			disableChecks = append(disableChecks, check.Name)
		}
	}

	err := s.checksService.EnableChecks(enableChecks)
	if err != nil {
		return nil, errors.Wrap(err, "failed to enable disabled security checks")
	}

	err = s.checksService.DisableChecks(disableChecks)
	if err != nil {
		return nil, errors.Wrap(err, "failed to disable security checks")
	}

	return &managementpb.ChangeSecurityChecksResponse{}, nil
}

// parses the check script and returns the docstring for the `check_context` function.
func (s *ChecksAPIService) getCheckDescription(check check.Check) string {
	// TODO There is similar code in check service; move this to a common package if possible.
	// https://jira.percona.com/browse/SAAS-429
	funcs, err := checks.GetFuncsForVersion(1)
	if err != nil {
		s.l.Warnf("%s: failed to get check description, %s", check.Name, err)
		return ""
	}
	predeclared := make(starlark.StringDict, len(funcs))
	for n, f := range funcs {
		predeclared[n] = starlark.NewBuiltin(n, saasStarlark.MakeFunc(f))
	}
	predeclared.Freeze()

	var thread starlark.Thread
	globals, err := starlark.ExecFile(&thread, "", check.Script, predeclared)
	if err != nil {
		s.l.Warnf("%s: failed to get check description, %s", check.Name, err)
		return ""
	}

	fun, ok := globals["check_context"].(*starlark.Function)
	if !ok {
		s.l.Warnf("%s: no `check_context` function found", check.Name)
		return ""
	}
	doc := strings.TrimSpace(fun.Doc())
	if doc == "" {
		s.l.Warnf("%s: `check_context` function should have docstring", check.Name)
		return ""
	}

	return doc
}
