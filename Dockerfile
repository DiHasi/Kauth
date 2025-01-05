FROM node:20 AS frontend-build
WORKDIR /frontend
COPY /web/package*.json ./
RUN npm install
COPY /web ./
RUN npm run generate

FROM golang:latest AS api-build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server cmd/main.go

FROM alpine:latest
WORKDIR /app
COPY --from=api-build /app/server ./server
COPY --from=frontend-build /frontend/.output/public ./web/dist
COPY configs ./configs
COPY migrations ./migrations

EXPOSE ${PORT}
CMD ["./server"]