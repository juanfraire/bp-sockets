@_default:
  just --list --list-submodules --unsorted

# Generate ION host.rc file
host ADDRESS_SOURCE ADDRESS_DEST:
  #!/usr/bin/python3

  import jinja2
  import yaml
  import sys
  
  if __name__ == "__main__":
    address_source = "{{ADDRESS_SOURCE}}"
    address_destination = "{{ADDRESS_DEST}}"
    template_file = "templates/host.rc.j2"

    env = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="."))

    template = env.get_template(template_file)
    print(template.render(address_source=address_source, address_destination=address_destination))