
Postgres Performance Analysis for Real Data
-----------
* pg_stat_statements
* Reference: http://freshpaint.io/blog/a-beginners-guide-to-postgres-performance-monitoring

## Installation of pg_stat_statements
* Running `sudo apt-get install postgres-contrib-${YOUR POSTGRES VERSION}`. This installs the postgres contrib package which provides additional functionality which is part of the official Postgres project, it's just not bundled with the default Postgres installation.
  * How to find Postgres version?
    * `psql -V` (example 11.11)
  * Example: `apt-get install postgres-contrib-11.11`
  * Note: Ubuntu install post-contrib install with the main repository, no need to install it separately. (https://www.postgresql.org/download/linux/ubuntu/)

* Add pg_stat_statements to the shared_preload_libraries in your postgres.conf file, like so: `shared_preload_libraries = 'pg_stat_statements'`.

* Restart Postgres. `sudo systemctl restart postgresql`

* Select the database:
  * `psql`
  * `\c <database-name>`

* Run `CREATE EXTENSION pg_stat_statements;`.

* Verify: `\d pg_stat_statements;`


## See the statistics

Reference: https://www.postgresql.org/docs/9.4/pgstatstatements.html

* Top 10 queries by total execution time:
  * `SELECT total_time, (total_time/calls) AS mean_time, calls, query FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;`

* Top 10 queries by number of execution:
  * `SELECT total_time, (total_time/calls) AS mean_time, calls, query FROM pg_stat_statements ORDER BY calls DESC LIMIT 10;`

* Top 10 queries by mean(avg) execution time:
  * `SELECT total_time, (total_time/calls) AS mean_time, calls, query FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;`


## Benchmarking 2021

* Hardware Configuration:
  * GCP Instance - e2 medium
  * 2 vCPUs
  * 4 GB Memory
  * Storage - 50 GB - Balanced persistent disk
  * Running all Shadow Collector and API on the same machine

* 15 Shadow Collector (Each runs every 10 seconds)
* Started processing at 00:45 IST (6th May 2021)

* Ended processes at 16:20 IST (6th May 2021)
  * Somehow shadow collector processes were stopped earlier we don't know yet when. (As logger currently do not display PID.)

* See `postgres_benchmarking_2021_05_06.py` file for benchmarking with actual queries.

* Please find time-estimation per request in `postgres_mal_ips_add_sc_performance_benchmarking_2021_05_06.xlsx` file.

