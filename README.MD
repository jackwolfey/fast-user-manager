# fast_user_manager

### a basic but useful user management service with fastapi

#### Run Service
clone this repo first and then
```shell
pip install -r requirements.txt
python fast_user_manager.py
```

#### Use Api

```python
import requests

r = requests.post('http://localhost:8090/add',
                  json={'username': 'john', 'password': 'abc'},
                  timeout=10)
print(r.text)

# {"code":0,"msg":"success"}
```

After you first run, there will be two files generated at dir

`db_secret.key` is the secret key to encrypt and decrypt the database

`user_data.pdb` stores all user date, it's the database file

For more example, please refer test_api.py
