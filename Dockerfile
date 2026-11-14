FROM php:8.4-cli-bookworm

WORKDIR /srv/lab
COPY --chown=33:33 upload.php ./
RUN mkdir -p /srv/lab/uploads \
    && chown 33:33 /srv/lab/uploads \
    && chmod 0700 /srv/lab/uploads

USER 33:33
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/srv/lab"]
