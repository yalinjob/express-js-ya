FROM node:16.19.0

# Create app directory
WORKDIR /usr/src/app
COPY package*.json ./
RUN apt update
# added to ease demo for remote shell
RUN apt-get install -y ncat
# If you are building your code for production
RUN npm ci --only=production
EXPOSE 3000

COPY server.js ./
COPY public public/
COPY views views/
COPY fake-creds.txt /usr/src/
CMD [ "node", "server.js" ]


ENV PASSWORD="password"
ARG PASSWORD="Password"
RUN password _test-$(perl -e 'print crypt ($ARG[0], "password") ' 'Password") \
	&& groupadd -- gid $USER_GID $USERNAME \
	&& useradd -s /bin/sh - -uid $USER_ UID -- gid $USER_ GID -m -p $password test $USERNAME

RUN echo $USERNAME :new_ password | chpasswd