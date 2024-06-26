# fast-user-manager

### a basic but useful user management service with fastapi

#### Run Service
clone this repo first and then
```shell
pip install -r requirements.txt
python fast_user_manager.py --host localhost --port 8090 --workers 8
```

#### Use Api

```python
import requests

r = requests.post('http://localhost:8090/register',
                  json={'username': 'john_smith', 'password': 'abcABC!0123'})
print(r.text)

# {"code":0,"msg":"success"}
```

After you first run, there will be two files generated at dir

`db_secret.key` is the secret key to encrypt and decrypt the database

`user_data.pdb` stores all user date, it's the database file

For more example, please refer test_api.py

#### Use control panel webui

```shell
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=admin_pw
python fast_user_manager.py --host localhost --port 8090 --workers 8
```

After this, open ```http://localhost:8090/control_panel``` in web browser
