# A simple weather application
- Just a simple weather application for me to learn about building a website and API call.
- CSS will not be added to this project, but... will be added in the future :)

## Update
- Updated weather app running with Docker🐳.

### How to use
+ Clone the repository:
```
git clone https://github.com/OceanTran999/SIMPLE-WEATHER-APP.git
cd SIMPLE-WEATHER-APP
```

+ Create image and container:
```
docker build -t <image_name> .
docker run -d -p <host_port:container_port> --name <container_name> <image_name>
```

+ After running successfully. Connect to the app with http://localhost:port or http://ip_host:port_host

<img width="728" height="974" alt="weather-demo" src="https://github.com/user-attachments/assets/e077b91f-4bcd-46f7-909e-ff168806a873" />
