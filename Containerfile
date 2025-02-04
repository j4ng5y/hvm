FROM cgr.dev/chainguard/go:latest

ENTRYPOINT [ "/hvm" ]

COPY hvm /
