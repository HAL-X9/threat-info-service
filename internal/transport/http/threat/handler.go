package threat

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/HAL-X9/threat-info-service/internal/domain"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/gen"
)

type Service interface {
	Create(ctx context.Context, md5 domain.MD5, details domain.Details) (domain.Threat, error)
	Get(ctx context.Context, md5 domain.MD5) (domain.Threat, error)
	Update(ctx context.Context, md5 domain.MD5, details domain.Details) (domain.Threat, error)
}

type Handler struct {
	service Service
	log     *slog.Logger
}

func NewHandler(service Service, log *slog.Logger) *Handler {
	return &Handler{service: service, log: log}
}

func (h *Handler) Register(mux *http.ServeMux) {
	strict := gen.NewStrictHandlerWithOptions(h, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  h.requestError,
		ResponseErrorHandlerFunc: h.responseError,
	})

	gen.HandlerFromMux(strict, mux)
}

func (h *Handler) CreateThreat(ctx context.Context, req gen.CreateThreatRequestObject) (gen.CreateThreatResponseObject, error) {
	md5, err := domain.ParseMD5(req.Body.Md5)
	if err != nil {
		return nil, err
	}

	details := toDetails(req.Body.Name, req.Body.Severity, req.Body.Category, req.Body.Description, req.Body.Tags)

	threat, err := h.service.Create(ctx, md5, details)
	if err != nil {
		return nil, err
	}

	return gen.CreateThreat201JSONResponse(toResponse(threat)), nil
}

func (h *Handler) GetInfoByMd5(ctx context.Context, req gen.GetInfoByMd5RequestObject) (gen.GetInfoByMd5ResponseObject, error) {
	md5, err := domain.ParseMD5(req.Md5)
	if err != nil {
		return nil, err
	}

	threat, err := h.service.Get(ctx, md5)
	if err != nil {
		return nil, err
	}

	return gen.GetInfoByMd5200JSONResponse(toResponse(threat)), nil
}

func (h *Handler) UpdateThreat(ctx context.Context, req gen.UpdateThreatRequestObject) (gen.UpdateThreatResponseObject, error) {
	md5, err := domain.ParseMD5(req.Md5)
	if err != nil {
		return nil, err
	}

	details := toDetails(req.Body.Name, req.Body.Severity, req.Body.Category, req.Body.Description, req.Body.Tags)

	threat, err := h.service.Update(ctx, md5, details)
	if err != nil {
		return nil, err
	}

	return gen.UpdateThreat200JSONResponse(toResponse(threat)), nil
}

func toDetails(name string, severity gen.Severity, category gen.Category, description *gen.Description, tags *gen.Tags) domain.Details {
	details := domain.Details{
		Name:     name,
		Severity: domain.Severity(severity),
		Category: domain.Category(category),
	}

	if description != nil {
		details.Description = *description
	}

	if tags != nil {
		details.Tags = *tags
	}

	return details
}

func toResponse(threat domain.Threat) gen.ThreatResponse {
	resp := gen.ThreatResponse{
		Md5:       threat.MD5.String(),
		Name:      threat.Name,
		Severity:  gen.Severity(threat.Severity),
		Category:  gen.Category(threat.Category),
		Tags:      threat.Tags,
		CreatedAt: threat.CreatedAt,
		UpdatedAt: threat.UpdatedAt,
	}

	if threat.Description != "" {
		resp.Description = &threat.Description
	}

	return resp
}
