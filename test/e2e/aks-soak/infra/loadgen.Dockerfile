# Load generator image: fortio's static binary on top of a shell-capable base so
# run.ps1's periodic "batch" loop (write -json, snapshot, repeat) works. The
# stock fortio/fortio image is distroless (no /bin/sh), which breaks the loop and
# leaves no way to snapshot interim reports during the 6h soak. Built to ACR so
# both loadgen pods pull it locally (image pull is not pod egress, so it is not
# subject to aksh capture/policy).
FROM fortio/fortio:1.66.3 AS fortio
FROM mcr.microsoft.com/cbl-mariner/busybox:2.0
COPY --from=fortio /usr/bin/fortio /usr/bin/fortio
ENTRYPOINT ["/bin/sh"]
