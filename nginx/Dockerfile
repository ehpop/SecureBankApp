FROM byjg/nginx-extras:1.25

RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/conf.d

COPY SecureBankApp.crt /etc/ssl/certs/bank.com.crt
COPY SecureBankApp.key /etc/ssl/private/bank.com.key
COPY example_password_file /etc/ssl/private/bank.com.pass