# wordpress

1. Start containers.

```bash
docker-compose up -d
```

2. Start furui.

```Bash
cargo xtask run -- ./example/wordpress/policy.yaml -i <iface>
```

3. You will now be able to access wordpress with a browser or cli.
