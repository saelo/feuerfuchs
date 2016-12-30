#!/usr/bin/env python3
#
# Challenge server for the "feuerfuchs" challenge of 33C3 CTF.
#
# Copyright (c) 2016 Samuel Groß
#

from urllib.parse import urlparse
from os.path import dirname, abspath
import subprocess
import asyncio
import docker
import json
import hmac

docker_client = docker.from_env()

HOST    = '127.0.0.1'
PORT    = 0xf1f0
FLAG    = "33C3_wh4t_d0e5_th3_f0x_s4y?"
SECRET  = b"Saeyoozouy5hee6Vfeuerfuchs"
WORKDIR = dirname(abspath(__file__))

MAX_RUNNING_CONTAINERS = 1
CONTAINER_TIMEOUT      = 30          # in seconds
MAX_TRIES              = 5

class Authenticator:
    # TODO something like redis would probably be better...
    def __init__(self, dbname):
        self._dbname = dbname
        try:
            with open(dbname, 'r') as f:
                try:
                    self._tokens = json.load(f)
                except json.decoder.JSONDecodeError:
                    print("Token database is corrupted, starting with a new one...")
                    self._tokens = {}
        except FileNotFoundError:
            print("Using fresh token database")
            self._tokens = {}

    def is_valid_token(self, token):
        if token[1] in self._tokens:
            return True
        team_id = token[0]
        expected = hmac.new(SECRET, str(team_id).encode('ascii'), "sha1").hexdigest()
        if expected == token[1]:
            self._tokens[token[1]] = 0
            return True
        else:
            return False

    def token_usages(self, token):
        return self._tokens[token[1]]

    def use_token(self, token):
        assert(token[1] in self._tokens)
        if token[0] != -1:
            self._tokens[token[1]] += 1
            with open(self._dbname, 'w+') as f:
                json.dump(self._tokens, f)

authenticator = Authenticator(WORKDIR + '/token_database')

class Client:
    def __init__(self, peer, reader, writer):
        self._peer = peer[0]
        self._reader = reader
        self._writer = writer
        self.container = None

    async def write(self, msg, end='\n'):
        self._writer.write((msg + end).encode('UTF-8'))
        await self._writer.drain()

    async def readline(self):
        line = await self._reader.readline()
        if not line:
            raise ConnectionResetError()
        return line.decode('UTF-8').strip()

    async def send_welcome(self):
        await self.write("""Welcome!

In this challenge you are asked to pwn a modified firefox and pop calc (xcalc to be specific). You can get the patch, as well as all other relevant files from here: https://33c3ctf.ccc.ac/uploads/feuerfuchs-f23f889382ed13a0e185fe48132c56eebf2b87f3.tar.xz

This challenge will work as follows:

    1. I'll ask you for your token

    2. I'll ask you for a URL to your exploit

    3. I'll start up a container, and within that open Firefox with your URL

    4. I'll see if there is a calculator process (xcalc) running inside the container, in which case I'll send you the flag. You have {} seconds to pop calc.

    5. I'll destroy the container

Enjoy!
~saelo
""".format(CONTAINER_TIMEOUT))

    async def verify_token(self, token):
        valid = authenticator.is_valid_token(token)
        if valid:
            tries = authenticator.token_usages(token)
            if tries < MAX_TRIES:
                print("Got valid token from {}: {}".format(self._peer, token))
                await self.write("Ok. You have {} tries left".format(MAX_TRIES - tries))
                return True
            else:
                print("Got expired token from {}: {}".format(self._peer, token))
                await self.write("Sorry, you already had {} attempts...".format(MAX_TRIES))
                return False
        else:
            print("Got invalid token from {}: {}".format(self._peer, token))
            await self.write("Invalid Token")
            return False

    async def use_token(self, token):
        authenticator.use_token(token)
        await self.write("You now have {} tries left".format(MAX_TRIES - authenticator.token_usages(token)))

    async def receive_token(self):
        await self.write("Your token please ('team_id:sha1'):")
        while True:
            line = await self.readline()
            try:
                team_id, hmac = line.split(':')
                return int(team_id), hmac
            except ValueError:
                await self.write("Try again")

    async def receive_url(self):
        def is_valid(url):
            parsed_url = urlparse(url)
            return parsed_url.scheme and parsed_url.netloc

        await self.write("Send me the URL to your exploit please:")
        url = await self.readline()
        while not is_valid(url):
            await self.write("That doesn't look like a valid URL to me. Try again")
            url = await self.readline()

        print("Got URL from {}: {}".format(self._peer, url))
        return url

    async def fetch_exploit(self, url, team_id, trynr):
        # Yes, I do want those Firefox 0days ;)
        proc = subprocess.Popen(["wget", "-p", "-k", "-P", WORKDIR + "/tries/team_{}_try_{}".format(team_id, trynr), url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(5)
        proc.kill()

    def num_running_containers(self):
        containers = docker_client.containers()
        return len(containers)

    async def start_container(self, url):
        need_newline = False
        if self.num_running_containers() >= MAX_RUNNING_CONTAINERS:
            await self.write("I cannot launch more containers right now, pleases hang on")
            while self.num_running_containers() >= MAX_RUNNING_CONTAINERS:
                await self.wait(5, send_newline=False)
                need_newline = True

            # There is no race here as long as we don't have another `await` call before the container is started

        config = docker_client.create_host_config()     # TODO limit memory and CPU?

        # Need a separate initial process to prevent the container from shutting down if the firefox process crashes.
        # The timeout is fairly large to prevent the container from prematurely shutting down if the server is very busy.
        self.container = docker_client.create_container(image='saelo/feuerfuchs', command=['/bin/sleep', str(60 * 5 + CONTAINER_TIMEOUT)], host_config=config)
        docker_client.start(self.container.get('Id'))

        firefox_exec = docker_client.exec_create(self.container.get('Id'), cmd=['/home/websurfer/launch_firefox.sh', url])
        docker_client.exec_start(firefox_exec.get('Id'), stream=True)

        if need_newline:
            await self.write("")

    def check_for_process(self, pname):
        pgrep_exec = docker_client.exec_create(self.container.get('Id'), cmd=['pgrep', pname])
        return len(docker_client.exec_start(pgrep_exec.get('Id'))) > 0

    async def check_pwned(self):
        await self.write("I'll now check for a calc process every 5 seconds for a total of up to {} seconds".format(CONTAINER_TIMEOUT))
        for i in range(0, CONTAINER_TIMEOUT, 5):
            await self.wait(5, send_newline=False)
            if self.check_for_process('xcalc'):
                await self.write(" ✓")
                return True
            else:
                await self.write(" ✗")
        return False

    def stop_container(self):
        if self.container:
            try:
                docker_client.kill(self.container.get('Id'))
            except docker.errors.APIError:
                # Could happen if the container has already stopped
                pass
            docker_client.remove_container(self.container.get('Id'))

    async def wait(self, time, send_newline=True):
        for i in range(time):
            await asyncio.sleep(1)
            await self.write('.', end='')
        if send_newline:
            await self.write('')

    async def serve(self):
        print("Connection from {}".format(self._peer))

        await self.send_welcome()

        token = await self.receive_token()

        if await self.verify_token(token):
            url = await self.receive_url()

            try:
                await self.start_container(url)

                await self.write("Your container has been started and should now browse to your URL")

                await self.use_token(token)

                if await self.check_pwned():
                    await self.write("Congrats, you popped calc! Here is your flag: " + FLAG)
                    print("{} popped calc!".format(self._peer))
                    await self.fetch_exploit(url, token[0], authenticator.token_usages(token))
                else:
                    await self.write("Sorry, seems like you didn't pop calc :(")
                    print("{} didn't pop calc".format(self._peer))
            finally:
                self.stop_container()


async def handle_client(reader, writer):
    peer = writer.get_extra_info('peername')
    client = Client(peer, reader, writer)
    try:
        await client.serve()
    except ConnectionResetError:
        pass
    except docker.errors.APIError:
        print("Oops, docker exception caught...")
    finally:
        writer.close()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_client, HOST, PORT)
    server = loop.run_until_complete(coro)

    print("Serving on {}".format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
