FROM composer@sha256:20462d70afcfa999ad75dbd9333194067f4d869078bdb37430339e8d97e541d6 AS build
WORKDIR /adapter
COPY composer.json composer.lock adapter.php ./
RUN composer install --no-dev --no-interaction --no-plugins --no-scripts --prefer-dist

FROM php@sha256:127ee0c063c5405c0a890383bfecd36c1637d1696bf3ac451cbfb5acb7350b28
WORKDIR /adapter
COPY --from=build /adapter /adapter
ENTRYPOINT ["php", "/adapter/adapter.php"]
