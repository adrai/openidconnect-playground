    $ npm install -g anvil-connect

start redis-server

execute setup scripts:

    $ "cd anvil && npm install"
    $ "cd client && npm install"
    $ nv init
    $ nv migrate
    $ ./anvil/taibika-setup.sh

start anvil server:

    $ node anvil/server.js

start client server:

    $ node client/server.js

go to http://localhost:3001

login in with a@b.c 123
