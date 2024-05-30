# Build aşaması
FROM golang:1.22.3-alpine AS builder

# Çalışma dizinini ayarla
WORKDIR /app

# Gerekli paketleri yükle
RUN apk update && apk add --no-cache sqlite sqlite-dev gcc musl-dev

# Uygulama kaynak kodunu kopyala
COPY . .

# CGO'yu etkinleştir ve Go uygulamasını derle
ENV CGO_ENABLED=1
RUN go build -o main .

# Çalışma aşaması
FROM alpine:latest

# Gerekli paketleri yükle (libc6-compat, libgcc ve libstdc++ gibi)
RUN apk update && apk add --no-cache sqlite-libs libc6-compat

# Çalışma dizinini ayarla
WORKDIR /app

# Derlenmiş binary'yi ve diğer gerekli dosyaları kopyala
COPY --from=builder /app/main .
COPY --from=builder /app/templates /app/templates

# Varsayılan komutu ayarla
CMD ["/app/main"]
