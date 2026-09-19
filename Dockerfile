# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS frontend
WORKDIR /src/frontend
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM golang:1.27.1-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/frontend/dist ./frontend/dist
# modernc.org/sqlite is pure Go, so the binary links statically without cgo.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/semgate-example .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=backend /out/semgate-example /semgate-example
ENV SEMGATE_EXAMPLE_ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["/semgate-example"]
CMD ["serve"]
