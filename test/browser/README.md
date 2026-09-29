# Browser tests

These drive a real browser against a running LogGen, covering what unit tests
cannot: that the console renders the catalogue, that filtering and search reach
the right records, that the destination state is reported honestly, and that
sending a record puts it on screen.

## Running them

Start LogGen and a sink, point a destination at the sink, then run the suite:

```sh
# one terminal
go build -o loggen .
./loggen -sink :5514

# another
./loggen -addr 127.0.0.1:8088 -open=false -data /tmp/loggen-test
curl -s -X POST http://127.0.0.1:8088/api/profiles \
  -H 'Content-Type: application/json' \
  -d '{"name":"Test sink","host":"127.0.0.1","port":5514,"protocol":"udp","isDefault":true}'

# then
cd test/browser
npm install
npx playwright install chromium
npm test
```

`BASE` overrides the URL:

```sh
BASE=http://127.0.0.1:9000 npm test
```

The suite creates a custom control on a source called `browsertest` and deletes
it again, so point it at a throwaway data directory rather than one you care
about.

CI runs this on every push; see `.github/workflows/ci.yml`.
