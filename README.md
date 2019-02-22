# SubwayRanks Backend
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FSubwayRanks%2FBackend.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2FSubwayRanks%2FBackend?ref=badge_shield)

## Installation

```bash
npm install

npm start
```

## URL

* API endpoint: http://localhost:3000
* Swagger UI: http://localhost:3000/api/docs
* Swagger json: http://localhost:3000/api/docs/swagger

## Немного про IDEA/WebStorm
В первый раз запусти
```bash
npm run tsc:w
```
Потом идем в Run Configurations, создаем конфигурацию node.js, как стартовый скрипт указываем `server/app.js`.
После этого можно будет ставить брейкпоинты в идее прямо в typescript-коде.
Дебаг будет тоже работать полностью: в переменные можно подсматривать и т.д.
Проверь что в settings->languages&frameworks->typescript правильно все натроено и стоит галка `recompile on changes` 


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FSubwayRanks%2FBackend.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FSubwayRanks%2FBackend?ref=badge_large)