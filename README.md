### INF601 - Advanced Programming in Python
### Josefina Baro
### Final Project


# PhishGuard


## Description

This project uses TotalVirus' API to check urls for potential phishing scams.
Users can check urls without logging in but can create an account to keep track of urls they have checked.
There are a total of 4 pages: home page, registration page, phishing awareness page, and a dashboard.
Dashboard page can only be accessed by registered users. 


### Installing

```
pip install -r requirements.txt
pip install requests
python -m pip install Django
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

### Executing program

* To start server

```
python manage.py runserver
```

## Authors

Josefina Baro


## Acknowledgments

Inspiration, code snippets, etc.
* [ChatGPT](https://chatgpt.com/share/675aa39a-9cd0-800d-9027-37a323bea3c1)
* [Bootswatch](https://bootswatch.com/)
* [VirusTotal](https://docs.virustotal.com/reference/overview)
