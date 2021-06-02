
#### To Install Postgres
- Ubuntu: https://www.postgresql.org/download/linux/ubuntu/
- CentOS: https://www.postgresql.org/download/linux/redhat/
- Windows: https://www.postgresql.org/download/windows/

#### Prepare Postgres

1. Switch to postgres user on the instance.
```
sudo su postgres
```
2. Run command `psql` to launch the psql interactive session.
3. Run below commands in psql window to prepare the postgres server.
```
CREATE DATABASE test;
CREATE USER <user-name> WITH ENCRYPTED PASSWORD '<password>';
GRANT ALL PRIVILEGES ON DATABASE test to <user-name>;
```
4. Come back to the user by which you are using to run the API server.


### Create Tables and Prepare Postgres Database
* Go to the latest version of database.
```
alembic upgrade head
```
* Downgrade the database to last changed.
```
alembic downgrade -1
```
* Generate new database revision.
```
alembic revision --autogenerate -m "Added account table"
```

### Postgres CLI Commands Reference
* List the database
    ```
    \l
    ```
* Select the database.
    ```
    \c <database-name>
    ```
* List the tables in the database
    ```
    \d
    ```
* Run SQL query:
    ```
    SELECT * FROM users;
    ```
