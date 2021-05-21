export
.PHONY: install
install:
	sudo apt-get install python3-pip
	pip3 install -r requirements.txt
.PHONY: dev-run
dev-run:
	uvicorn main:app --reload --host 0.0.0.0 --port 8080 --log-level debug
.PHONY: migrate
migrate:
	alembic upgrade head
.PHONY: prod-run
prod-run:
	gunicorn main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8080 --log-level debug --daemon
.PHONY: prod-https
prod-https:
	gunicorn main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8080 --log-level debug --keyfile=./certificates/key.pem --certfile=./certificates/cert.pem --daemon
.PHONY: prod-https-ca
prod-https-ca:
	gunicorn main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8080 --log-level debug --keyfile=./certificates/key.pem --certfile=./certificates/cert.pem --ca-certs=./certificates/ca-cert.pem --daemon
