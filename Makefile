app:
	docker-compose up -d app

debug: app
	docker-compose exec app bash

build:
	docker-compose run --rm app ./codeship/build.sh

test:
	docker-compose run --rm app ./codeship/test.sh

clean:
	docker-compose kill
	docker-compose rm -f