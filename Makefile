
FLY_APP = incase
FLY_DB = incase-db
FLY_REGION = ams

default: test

.PHONY: test
test: fuzz
	go test --race ./...

fuzz:
	go test -v -fuzz=Fuzz -fuzztime 90s ./...

# --- Fly.io deployment ---

.PHONY: fly-create fly-db fly-attach fly-deploy fly-up fly-down fly-status fly-logs

## Create the Fly app (run once)
fly-create:
	fly apps create $(FLY_APP) --machines

## Create and attach Postgres
fly-db:
	fly postgres create --name $(FLY_DB) --region $(FLY_REGION)

fly-attach:
	fly postgres attach $(FLY_DB) --app $(FLY_APP)

## Deploy the app
fly-deploy:
	fly deploy

## Full setup: create app, db, attach, deploy
fly-up: fly-create fly-db fly-attach fly-deploy

## Tear everything down
fly-down:
	-fly apps destroy $(FLY_APP) --yes
	-fly apps destroy $(FLY_DB) --yes

## Helpers
fly-status:
	fly status --app $(FLY_APP)

fly-logs:
	fly logs --app $(FLY_APP)

