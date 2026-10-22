# CommitWindow

Send one HTTP/1.1 request, close its connection at a chosen point, then check for its effect with a separate GET.

Supply raw HTTP/1.1 request files for the write and the readback. Both must contain `${marker}`; the readback must be a bodyless GET.

```sh
python3 commitwindow.py --origin https://target.example --request write.http --verify readback.http --cut after-body --out result.json
```

`--cut after-headers` closes before the body. `--cut delay --delay-ms 200` waits after sending the body and records any response bytes seen before closing. The default close uses a TCP reset; `--close fin` sends a FIN. For HTTPS, certificate verification is on by default; `--insecure` is available for a lab certificate.

Verification requires HTTP 200 and the marker in the response body. Use `--verify-mode status --verify-status 204` if the readback is established by status alone. The baseline GET must not already match. Readback polls for five seconds by default; `--verify-window` and `--verify-interval` change that window.

The JSON report records socket-call times, bytes seen before closing, verification statuses, and body hashes. `state_observed_on_readback` means the marker appeared on a later read. `trial.client_cut` is false if the server closed first. The report cannot establish the server's exact commit time.
