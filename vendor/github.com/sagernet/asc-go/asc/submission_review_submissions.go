/**
Copyright (C) 2020 Aaron Sky.

This file is part of asc-go, a package for working with Apple's
App Store Connect API.

asc-go is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

asc-go is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with asc-go.  If not, see <http://www.gnu.org/licenses/>.
*/

package asc

import (
	"context"
	"fmt"
)

// ReviewSubmissionState defines model for ReviewSubmission.Attributes.State.
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmission/attributes
type ReviewSubmissionState string

const (
	// ReviewSubmissionStateReadyForReview is a review submission state for ReadyForReview.
	ReviewSubmissionStateReadyForReview ReviewSubmissionState = "READY_FOR_REVIEW"
	// ReviewSubmissionStateWaitingForReview is a review submission state for WaitingForReview.
	ReviewSubmissionStateWaitingForReview ReviewSubmissionState = "WAITING_FOR_REVIEW"
	// ReviewSubmissionStateInReview is a review submission state for InReview.
	ReviewSubmissionStateInReview ReviewSubmissionState = "IN_REVIEW"
	// ReviewSubmissionStateUnresolvedIssues is a review submission state for UnresolvedIssues.
	ReviewSubmissionStateUnresolvedIssues ReviewSubmissionState = "UNRESOLVED_ISSUES"
	// ReviewSubmissionStateCanceling is a review submission state for Canceling.
	ReviewSubmissionStateCanceling ReviewSubmissionState = "CANCELING"
	// ReviewSubmissionStateCompleting is a review submission state for Completing.
	ReviewSubmissionStateCompleting ReviewSubmissionState = "COMPLETING"
	// ReviewSubmissionStateComplete is a review submission state for Complete.
	ReviewSubmissionStateComplete ReviewSubmissionState = "COMPLETE"
)

// ReviewSubmission defines model for ReviewSubmission.
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmission
type ReviewSubmission struct {
	Attributes    *ReviewSubmissionAttributes    `json:"attributes,omitempty"`
	ID            string                         `json:"id"`
	Links         ResourceLinks                  `json:"links"`
	Relationships *ReviewSubmissionRelationships `json:"relationships,omitempty"`
	Type          string                         `json:"type"`
}

// ReviewSubmissionAttributes defines model for ReviewSubmission.Attributes
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmission/attributes
type ReviewSubmissionAttributes struct {
	Platform      *Platform              `json:"platform,omitempty"`
	State         *ReviewSubmissionState `json:"state,omitempty"`
	SubmittedDate *DateTime              `json:"submittedDate,omitempty"`
}

// ReviewSubmissionRelationships defines model for ReviewSubmission.Relationships
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmission/relationships
type ReviewSubmissionRelationships struct {
	App                      *Relationship      `json:"app,omitempty"`
	AppStoreVersionForReview *Relationship      `json:"appStoreVersionForReview,omitempty"`
	Items                    *PagedRelationship `json:"items,omitempty"`
}

// ReviewSubmissionResponse defines model for ReviewSubmissionResponse.
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionresponse
type ReviewSubmissionResponse struct {
	Data  ReviewSubmission `json:"data"`
	Links DocumentLinks    `json:"links"`
}

// ReviewSubmissionsResponse defines model for ReviewSubmissionsResponse.
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionsresponse
type ReviewSubmissionsResponse struct {
	Data  []ReviewSubmission `json:"data"`
	Links PagedDocumentLinks `json:"links"`
	Meta  *PagingInformation `json:"meta,omitempty"`
}

// ReviewSubmissionItem defines model for ReviewSubmissionItem.
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionitem
type ReviewSubmissionItem struct {
	Attributes    *ReviewSubmissionItemAttributes    `json:"attributes,omitempty"`
	ID            string                             `json:"id"`
	Links         ResourceLinks                      `json:"links"`
	Relationships *ReviewSubmissionItemRelationships `json:"relationships,omitempty"`
	Type          string                             `json:"type"`
}

// ReviewSubmissionItemAttributes defines model for ReviewSubmissionItem.Attributes
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionitem/attributes
type ReviewSubmissionItemAttributes struct {
	State *string `json:"state,omitempty"`
}

// ReviewSubmissionItemRelationships defines model for ReviewSubmissionItem.Relationships
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionitem/relationships
type ReviewSubmissionItemRelationships struct {
	AppStoreVersion *Relationship `json:"appStoreVersion,omitempty"`
}

// ReviewSubmissionItemResponse defines model for ReviewSubmissionItemResponse.
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionitemresponse
type ReviewSubmissionItemResponse struct {
	Data  ReviewSubmissionItem `json:"data"`
	Links DocumentLinks        `json:"links"`
}

// ReviewSubmissionItemsResponse defines model for ReviewSubmissionItemsResponse.
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionitemsresponse
type ReviewSubmissionItemsResponse struct {
	Data  []ReviewSubmissionItem `json:"data"`
	Links PagedDocumentLinks     `json:"links"`
	Meta  *PagingInformation     `json:"meta,omitempty"`
}

// reviewSubmissionCreateRequest defines model for ReviewSubmissionCreateRequest.
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissioncreaterequest/data
type reviewSubmissionCreateRequest struct {
	Attributes    *reviewSubmissionCreateRequestAttributes   `json:"attributes,omitempty"`
	Relationships reviewSubmissionCreateRequestRelationships `json:"relationships"`
	Type          string                                     `json:"type"`
}

// reviewSubmissionCreateRequestAttributes are attributes for ReviewSubmissionCreateRequest
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissioncreaterequest/data/attributes
type reviewSubmissionCreateRequestAttributes struct {
	Platform *Platform `json:"platform,omitempty"`
}

// reviewSubmissionCreateRequestRelationships are relationships for ReviewSubmissionCreateRequest
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissioncreaterequest/data/relationships
type reviewSubmissionCreateRequestRelationships struct {
	App relationshipDeclaration `json:"app"`
}

// reviewSubmissionUpdateRequest defines model for ReviewSubmissionUpdateRequest.
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionupdaterequest/data
type reviewSubmissionUpdateRequest struct {
	Attributes *reviewSubmissionUpdateRequestAttributes `json:"attributes,omitempty"`
	ID         string                                   `json:"id"`
	Type       string                                   `json:"type"`
}

// reviewSubmissionUpdateRequestAttributes are attributes for ReviewSubmissionUpdateRequest
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionupdaterequest/data/attributes
type reviewSubmissionUpdateRequestAttributes struct {
	Canceled  *bool `json:"canceled,omitempty"`
	Submitted *bool `json:"submitted,omitempty"`
}

// reviewSubmissionItemCreateRequest defines model for ReviewSubmissionItemCreateRequest.
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionitemcreaterequest/data
type reviewSubmissionItemCreateRequest struct {
	Relationships reviewSubmissionItemCreateRequestRelationships `json:"relationships"`
	Type          string                                         `json:"type"`
}

// reviewSubmissionItemCreateRequestRelationships are relationships for ReviewSubmissionItemCreateRequest
//
// https://developer.apple.com/documentation/appstoreconnectapi/reviewsubmissionitemcreaterequest/data/relationships
type reviewSubmissionItemCreateRequestRelationships struct {
	AppStoreVersion  *relationshipDeclaration `json:"appStoreVersion,omitempty"`
	ReviewSubmission relationshipDeclaration  `json:"reviewSubmission"`
}

// ListReviewSubmissionsQuery are query options for ListReviewSubmissions
//
// https://developer.apple.com/documentation/appstoreconnectapi/get-v1-reviewsubmissions
type ListReviewSubmissionsQuery struct {
	FieldsReviewSubmissions     []string `url:"fields[reviewSubmissions],omitempty,comma"`
	FieldsReviewSubmissionItems []string `url:"fields[reviewSubmissionItems],omitempty,comma"`
	FilterApp                   []string `url:"filter[app],comma"`
	FilterPlatform              []string `url:"filter[platform],omitempty,comma"`
	FilterState                 []string `url:"filter[state],omitempty,comma"`
	Include                     []string `url:"include,omitempty,comma"`
	Limit                       int      `url:"limit,omitempty"`
	LimitItems                  int      `url:"limit[items],omitempty"`
	Cursor                      string   `url:"cursor,omitempty"`
}

// ListItemsForReviewSubmissionQuery are query options for ListItemsForReviewSubmission
//
// https://developer.apple.com/documentation/appstoreconnectapi/get-v1-reviewsubmissions-_id_-items
type ListItemsForReviewSubmissionQuery struct {
	FieldsReviewSubmissionItems []string `url:"fields[reviewSubmissionItems],omitempty,comma"`
	FieldsAppStoreVersions      []string `url:"fields[appStoreVersions],omitempty,comma"`
	Include                     []string `url:"include,omitempty,comma"`
	Limit                       int      `url:"limit,omitempty"`
	Cursor                      string   `url:"cursor,omitempty"`
}

// ListReviewSubmissions lists review submissions of an app.
//
// https://developer.apple.com/documentation/appstoreconnectapi/get-v1-reviewsubmissions
func (s *SubmissionService) ListReviewSubmissions(ctx context.Context, params *ListReviewSubmissionsQuery) (*ReviewSubmissionsResponse, *Response, error) {
	res := new(ReviewSubmissionsResponse)
	resp, err := s.client.get(ctx, "reviewSubmissions", params, res)

	return res, resp, err
}

// CreateReviewSubmission creates a review submission for an app.
//
// https://developer.apple.com/documentation/appstoreconnectapi/post-v1-reviewsubmissions
func (s *SubmissionService) CreateReviewSubmission(ctx context.Context, appID string, platform *Platform) (*ReviewSubmissionResponse, *Response, error) {
	req := reviewSubmissionCreateRequest{
		Relationships: reviewSubmissionCreateRequestRelationships{
			App: *newRelationshipDeclaration(&appID, "apps"),
		},
		Type: "reviewSubmissions",
	}

	if platform != nil {
		req.Attributes = &reviewSubmissionCreateRequestAttributes{
			Platform: platform,
		}
	}

	res := new(ReviewSubmissionResponse)
	resp, err := s.client.post(ctx, "reviewSubmissions", newRequestBody(req), res)

	return res, resp, err
}

// UpdateReviewSubmission submits or cancels a review submission.
//
// https://developer.apple.com/documentation/appstoreconnectapi/patch-v1-reviewsubmissions-_id_
func (s *SubmissionService) UpdateReviewSubmission(ctx context.Context, id string, submitted *bool, canceled *bool) (*ReviewSubmissionResponse, *Response, error) {
	req := reviewSubmissionUpdateRequest{
		ID:   id,
		Type: "reviewSubmissions",
	}

	if submitted != nil || canceled != nil {
		req.Attributes = &reviewSubmissionUpdateRequestAttributes{
			Canceled:  canceled,
			Submitted: submitted,
		}
	}

	url := fmt.Sprintf("reviewSubmissions/%s", id)
	res := new(ReviewSubmissionResponse)
	resp, err := s.client.patch(ctx, url, newRequestBody(req), res)

	return res, resp, err
}

// ListItemsForReviewSubmission lists the items of a review submission.
//
// https://developer.apple.com/documentation/appstoreconnectapi/get-v1-reviewsubmissions-_id_-items
func (s *SubmissionService) ListItemsForReviewSubmission(ctx context.Context, id string, params *ListItemsForReviewSubmissionQuery) (*ReviewSubmissionItemsResponse, *Response, error) {
	url := fmt.Sprintf("reviewSubmissions/%s/items", id)
	res := new(ReviewSubmissionItemsResponse)
	resp, err := s.client.get(ctx, url, params, res)

	return res, resp, err
}

// CreateReviewSubmissionItemForAppStoreVersion adds an App Store version to a review submission.
//
// https://developer.apple.com/documentation/appstoreconnectapi/post-v1-reviewsubmissionitems
func (s *SubmissionService) CreateReviewSubmissionItemForAppStoreVersion(ctx context.Context, reviewSubmissionID string, appStoreVersionID string) (*ReviewSubmissionItemResponse, *Response, error) {
	req := reviewSubmissionItemCreateRequest{
		Relationships: reviewSubmissionItemCreateRequestRelationships{
			AppStoreVersion:  newRelationshipDeclaration(&appStoreVersionID, "appStoreVersions"),
			ReviewSubmission: *newRelationshipDeclaration(&reviewSubmissionID, "reviewSubmissions"),
		},
		Type: "reviewSubmissionItems",
	}

	res := new(ReviewSubmissionItemResponse)
	resp, err := s.client.post(ctx, "reviewSubmissionItems", newRequestBody(req), res)

	return res, resp, err
}
