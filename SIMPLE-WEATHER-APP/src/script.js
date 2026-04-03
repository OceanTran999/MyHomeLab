const api_key="02cb811b632f93d6aabc2a16a00ccf12";
const apiUrl = "https://api.openweathermap.org/data/2.5/weather?units=metric&q=";

// Input elements
const searchBox = document.querySelector('.input_search button');
const inputTxt = document.querySelector('.input_search input');

// Output elements
const cityName = document.querySelector('.city_name');
const weather = document.querySelector('.info');
const weatDesc = document.querySelector('.description');
const temper = document.querySelector('.temp');
const windSpeed = document.querySelector('.wind_speed');
var wea_info = document.querySelector('.weather-info');
const weather_ic = document.querySelector('.weather_icon');

async function give_details(city_name) {
    // wea_info.style.display = 'none';
    const resp = await fetch(`https://api.openweathermap.org/data/2.5/weather?q=${city_name}&appid=${api_key}`);
    var data = await resp.json();

    console.log(data);

    if(data.cod == 200){
        // wea_info.style.display = 'inline';
        cityName.innerHTML = "City name: " + inputTxt.value;

        // "Weather" is an Array
        weather.innerHTML = "Weather: " + data.weather[0].main;
        weatDesc.innerHTML = "Weather description: " + data.weather[0].description;

        temper.innerHTML = "Temperature: " + data.main.temp;
        windSpeed.innerHTML = "Speed of wind: " + data.wind.speed;

        // Handle display weather's icon
        switch(data.weather[0].main){
            case "Clouds":
                weather_ic.src = "img/clouds.png";
                break;
            case "Rain":
                weather_ic.src = "img/rainy.jpg";
                break;
            case "Wind":
                weather_ic.src = "img/wind.png";
                break;
            case "Snow":
                weather_ic.src = "img/snow.png";
                break;
            case "Mist":
                weather_ic.src = "img/mist.png";
                break;
        }
    }
    else{
        // Handle with invalid city
        cityName.innerHTML = "Can't find " + inputTxt.value;
        weather.innerHTML = '';
        weatDesc.innerHTML = '';
        temper.innerHTML = '';
        windSpeed.innerHTML = '';
    }
}

searchBox.addEventListener('click', function() {
    give_details(inputTxt.value);
});

inputTxt.addEventListener('keypress', function (event) {
    if(event.key == "Enter"){
        give_details(inputTxt.value);
    }

});
