app:
	docker-compose up -d app

debug: app
	docker-compose exec app bash

build:
	docker-compose run app ./codeship/build.sh

test:
	docker-compose run app ./codeship/test.sh

clean:
	docker-compose kill
	docker-compose rm -f