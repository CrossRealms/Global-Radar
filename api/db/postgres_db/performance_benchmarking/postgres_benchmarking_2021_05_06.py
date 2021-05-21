
# db_users.py
def get_user():
    '''
    Query: SELECT users.username AS users_username, users.email AS users_email, users.hashed_password AS users_hashed_password, users.role AS users_role FROM users WHERE users.username = $1;

    Total: 362.521889000002
    Avg: 0.0253476359250456
    Calls: 14302
    '''
    pass


# db_mal_ips.py
def add_shadow_collector_ips():
    '''
    71.8079580000002 | 0.00160092651714452 |  44854 | BEGIN
59.2189700000007 | 0.00132052558813693 |  44845 | COMMIT
    '''
    for _, device in device_list.devices.items():

        # Making sure device is present in the database
        db_device = self.db.query(MaliciousIPModel).get(device.ip)
        '''
        Query: SELECT malicious_ips.ip AS malicious_ips_ip, malicious_ips.count AS malicious_ips_count FROM malicious_ips WHERE malicious_ips.ip = $1

        Total: 1713.89873
        Avg: 0.040629118386118
        Calls: 42184
        '''

        if not db_device:
            db_device = MaliciousIPModel(
                ip = device.ip
            )
            self.db.add(db_device)
            '''
            Query: INSERT INTO malicious_ips (ip, count) VALUES ($1, $2)

            Total: 24.315365
            Avg: 0.0358633702064896
            Calls: 678
            '''
            self.db.commit()
        else:
            db_device.count += 1
            '''
            Query: UPDATE malicious_ips SET count=$1 WHERE malicious_ips.ip = $2
            
            Total: 1097.470029
            Acg: 0.0326841988504379
            Calls: 33578
            '''
        
        # Making sure source is present in the database
        db_source = self.db.query(MaliciousIPSourcesModel).filter(MaliciousIPSourcesModel.received_from==account_username and MaliciousIPSourcesModel.source == target_source).first()
        '''
        Query: SELECT malicious_ip_sources.id AS malicious_ip_sources_id, malicious_ip_sources.received_from AS malicious_ip_sources_received_from, malicious_ip_sources.source AS malicious_ip_sources_source FROM malicious_ip_sources WHERE malicious_ip_sources.received_from = $1 LIMIT $2;

        Total: 570.025383999999
        Avg: 0.0166401618402615
        Calls: 34256
        '''
        
        if not db_source:
            db_source = MaliciousIPSourcesModel(
                received_from = account_username,
                source = target_source,
            )
            self.db.add(db_source)
            '''
            Some query?
            '''
            self.db.commit()
        
        # Adding field-values(information about the device)
        information = db_device.get_information(self.db, db_source.id)
        '''
        Query: SELECT malicious_ip_information.bad_actor AS malicious_ip_information_bad_actor, malicious_ip_information.source_id AS malicious_ip_information_source_id, malicious_ip_information.field AS malicious_ip_information_field, malicious_ip_information.value AS malicious_ip_information_value, malicious_ip_information.last_detected AS malicious_ip_information_last_detected, malicious_ip_information.count AS malicious_ip_information_count FROM malicious_ip_information WHERE malicious_ip_information.bad_actor = $1

        Total: 61592.5033000009
        Avg: 0.148150427788323
        Calls: 415743
        '''

        for field in device.fields:
            for value in device.fields[field]:
                # create information if not present, otherwise update last_detected
                for i in information:
                    if i.field == field and i.value == value:
                        i.last_detected = datetime.datetime.now()
                        i.count += 1
                        break
                        '''
                        Query: UPDATE malicious_ip_information SET last_detected=$1::timestamp, count=$2 WHERE malicious_ip_information.bad_actor = $3 AND malicious_ip_information.source_id = $4 AND malicious_ip_information.field = $5 AND malicious_ip_information.value = $6

                        Total: 10385.097387
                        Avg: 0.0256361390559275
                        Calls: 405096
                        '''
                else:
                    info = MaliciousIPInformationModel(
                        bad_actor = db_device.ip,
                        source_id = db_source.id,
                        field = field,
                        value = value,
                    )
                    self.db.add(info)
                    '''
                    Query: INSERT INTO malicious_ip_information (bad_actor, source_id, field, value, last_detected, count) VALUES ($1, $2, $3, $4, $5::timestamp, $6)

                    Total: 1202.415941
                    Avg: 0.112934717854795
                    Calls: 10647
                    '''
                    self.db.commit()
        self.db.commit()

    '''
    Extra Query found in the analysis
    SELECT malicious_ip_sources.id AS malicious_ip_sources_id, malicious_ip_sources.received_from AS malicious_ip_sources_received_from, malicious_ip_sources.source AS malicious_ip_sources_source FROM malicious_ip_sources WHERE malicious_ip_sources.id = $1
    92.9836710000002 |  0.0128253339310345 |   7250
    '''

