# LogGen container image.
#
#   docker run --rm -p 8088:8088 -v loggen-data:/data ghcr.io/theshahrukh98khan/loggen
#
# The console is served on 8088 inside the container. Publishing that port makes
# it reachable from the host. A fresh volume signs in with admin/admin over
# plain HTTP, so bind it to a loopback address on the host
# (-p 127.0.0.1:8088:8088) unless the network is one you control, and change
# the password once you are in.

FROM golang:1.24-alpine AS build

WORKDIR /src

# There are no third-party dependencies, so the module files copy in one step.
COPY go.mod ./
COPY . .

# A fully static binary, so the final stage needs no libc at all.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o /out/loggen .

# The data directory has to exist here: the runtime stage has no shell to
# create one, and it needs to be owned by the unprivileged user.
RUN mkdir -p /out/data

# Distroless: no shell, no package manager, nothing to pivot to.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/loggen /loggen
COPY --from=build --chown=nonroot:nonroot /out/data /data

# Profiles and the simulated estate persist here.
VOLUME ["/data"]

EXPOSE 8088

USER nonroot:nonroot

ENTRYPOINT ["/loggen"]

# Bind to all interfaces because the container has its own network namespace;
# the host port publish decides who can actually reach it. No browser to open.
CMD ["-addr", "0.0.0.0:8088", "-open=false", "-data", "/data"]
