FROM node:16.19.0
ARG JF_URL
ARG JF_USER
ARG JF_ACCESS_TOKEN

# Create app directory
WORKDIR /usr/src/app
COPY package*.json ./

# Install required packages and JFrog CLI
RUN apt-get update && \
    apt-get install -y curl make ncat && \
    apt-get clean && \
    curl -fL https://install-cli.jfrog.io | sh && \
    mv jfrog /usr/local/bin/

# Verify JFrog CLI installation
RUN jfrog --version

# Configure JFrog CLI and install dependencies
RUN jfrog config add my-server-id \
    --artifactory-url=${JF_URL}/artifactory \
    --user=${JF_USER} \
    --access-token=${JF_ACCESS_TOKEN} \
    --interactive=false && \
    jfrog config use my-server-id && \
    jf npmc --server-id-resolve=my-server-id --repo-resolve=dev_npm_ya_virtual_version && \
    jf npm install --omit dev

# Expose the application port
EXPOSE 3000

# Copy the rest of the application code
COPY server.js ./
COPY public public/
COPY views views/
COPY creds.txt /usr/src/

# Start the application
CMD ["node", "server.js"]
