postgres:
	docker run --name postgres -e POSTGRES_PASSWORD=wow -e POSTGRES_DB=blockchains -p 5432:5432 -d postgres

dump-list:
	docker exec postgres psql -U postgres -d blockchain -t -c "SELECT DISTINCT address FROM nodes;" > result.txt
