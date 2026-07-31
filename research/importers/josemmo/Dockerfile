FROM composer@sha256:20462d70afcfa999ad75dbd9333194067f4d869078bdb37430339e8d97e541d6 AS build
WORKDIR /adapter
COPY composer.json composer.lock adapter.php ./
RUN composer install --no-dev --no-interaction --no-plugins --no-scripts --prefer-dist

FROM php@sha256:c6bd0893966623c6a2f9433d37f6f18db65593629da0f71417feb6cb78435a1e
WORKDIR /adapter
COPY --from=build /adapter /adapter
ENTRYPOINT ["php", "/adapter/adapter.php"]
