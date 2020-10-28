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
	"testing"

	"github.com/percona-platform/saas/pkg/check"
	"github.com/percona/pmm/api/managementpb"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/percona/pmm-managed/services"
	"github.com/percona/pmm-managed/utils/tests"
)

func TestStartSecurityChecks(t *testing.T) {
	t.Run("internal error", func(t *testing.T) {
		var checksService mockChecksService
		checksService.On("StartChecks", mock.Anything).Return(errors.New("random error"))

		s := NewChecksAPIService(&checksService)

		resp, err := s.StartSecurityChecks(context.Background())
		assert.EqualError(t, err, "failed to start security checks: random error")
		assert.Nil(t, resp)
	})

	t.Run("STT disabled error", func(t *testing.T) {
		var checksService mockChecksService
		checksService.On("StartChecks", mock.Anything).Return(services.ErrSTTDisabled)

		s := NewChecksAPIService(&checksService)

		resp, err := s.StartSecurityChecks(context.Background())
		tests.AssertGRPCError(t, status.New(codes.FailedPrecondition, "STT is disabled."), err)
		assert.Nil(t, resp)
	})
}

func TestGetSecurityCheckResults(t *testing.T) {
	t.Run("internal error", func(t *testing.T) {
		var checksService mockChecksService
		checksService.On("GetSecurityCheckResults", mock.Anything).Return(nil, errors.New("random error"))

		s := NewChecksAPIService(&checksService)

		resp, err := s.GetSecurityCheckResults()
		assert.EqualError(t, err, "failed to get security check results: random error")
		assert.Nil(t, resp)
	})

	t.Run("STT disabled error", func(t *testing.T) {
		var checksService mockChecksService
		checksService.On("GetSecurityCheckResults", mock.Anything).Return(nil, services.ErrSTTDisabled)

		s := NewChecksAPIService(&checksService)

		resp, err := s.GetSecurityCheckResults()
		tests.AssertGRPCError(t, status.New(codes.FailedPrecondition, "STT is disabled."), err)
		assert.Nil(t, resp)
	})

	t.Run("STT enabled", func(t *testing.T) {
		checkResult := []check.Result{
			{
				Summary:     "Check summary",
				Description: "Check Description",
				Severity:    1,
				Labels:      map[string]string{"label_key": "label_value"},
			},
		}
		response := &managementpb.GetSecurityCheckResultsResponse{
			Results: []*managementpb.SecurityCheckResult{
				{
					Summary:     "Check summary",
					Description: "Check Description",
					Severity:    1,
					Labels:      map[string]string{"label_key": "label_value"},
				},
			},
		}
		var checksService mockChecksService
		checksService.On("GetSecurityCheckResults", mock.Anything).Return(checkResult, nil)

		s := NewChecksAPIService(&checksService)

		resp, err := s.GetSecurityCheckResults()
		require.NoError(t, err)
		assert.Equal(t, resp, response)
	})
}

func TestListSecurityChecks(t *testing.T) {
	scriptWithDesc := strings.TrimSpace(`
	def check_context(rows, context):
		"""
		This check returns and empty list.
		"""
	
		return []
	`)

	scriptWithoutDesc := strings.TrimSpace(`
	def check_context(rows, context):
		
		return []
	`)

	scriptWithInvalidFunction := strings.TrimSpace(`
	def run(rows, context):
		
		return []
	`)

	invalidScript := "invalid script"
	t.Run("normal", func(t *testing.T) {
		var checksService mockChecksService
		checksService.On("GetDisabledChecks", mock.Anything).Return([]string{"two"}, nil)
		checksService.On("GetAllChecks", mock.Anything).
			Return([]check.Check{
				{Name: "one", Script: scriptWithDesc},
				{Name: "two", Script: scriptWithoutDesc},
				{Name: "three", Script: scriptWithInvalidFunction},
				{Name: "four", Script: invalidScript},
			})

		s := NewChecksAPIService(&checksService)

		resp, err := s.ListSecurityChecks()
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.ElementsMatch(t, resp.Checks,
			[]*managementpb.SecurityCheck{
				{Name: "one", Disabled: false, Description: "This check returns and empty list."},
				{Name: "two", Disabled: true, Description: ""},
				{Name: "three", Disabled: false, Description: ""},
				{Name: "four", Disabled: false, Description: ""},
			},
		)
	})

	t.Run("get disabled checks error", func(t *testing.T) {
		var checksService mockChecksService
		checksService.On("GetDisabledChecks", mock.Anything).Return(nil, errors.New("random error"))

		s := NewChecksAPIService(&checksService)

		resp, err := s.ListSecurityChecks()
		assert.EqualError(t, err, "failed to get disabled checks list: random error")
		assert.Nil(t, resp)
	})
}

func TestUpdateSecurityChecks(t *testing.T) {
	t.Run("enable security checks error", func(t *testing.T) {
		var checksService mockChecksService
		checksService.On("EnableChecks", mock.Anything).Return(errors.New("random error"))

		s := NewChecksAPIService(&checksService)

		resp, err := s.ChangeSecurityChecks(&managementpb.ChangeSecurityChecksRequest{})
		assert.EqualError(t, err, "failed to enable disabled security checks: random error")
		assert.Nil(t, resp)
	})

	t.Run("disable security checks error", func(t *testing.T) {
		var checksService mockChecksService
		checksService.On("EnableChecks", mock.Anything).Return(nil)
		checksService.On("DisableChecks", mock.Anything).Return(errors.New("random error"))

		s := NewChecksAPIService(&checksService)

		resp, err := s.ChangeSecurityChecks(&managementpb.ChangeSecurityChecksRequest{})
		assert.EqualError(t, err, "failed to disable security checks: random error")
		assert.Nil(t, resp)
	})
}
