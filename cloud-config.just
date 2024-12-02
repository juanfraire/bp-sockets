ssh_public_key := env_var('SSH_PUBLIC_KEY')

@_default:
  just --list --list-submodules --unsorted

# Generate a cloud-init file for ION node
ion-node:
  #!/usr/bin/python3

  import jinja2
  import yaml
  import os

  if __name__ == "__main__":
    ssh_public_key = "{{ssh_public_key}}"
    template_file = "templates/ion-node.debian.cfg.j2"
        
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="."))
    env.globals['getenv'] = lambda key: os.getenv(key)

    template = env.get_template(template_file)
    print(template.render())

# Generate a cloud-init file for µD3TN node
ud3tn-node:
  #!/usr/bin/python3

  import jinja2
  import yaml
  import os

  if __name__ == "__main__":
    ssh_public_key = "{{ssh_public_key}}"
    template_file = "templates/ud3tn-node.debian.cfg.j2"
        
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="."))
    env.globals['getenv'] = lambda key: os.getenv(key)

    template = env.get_template(template_file)
    print(template.render())
