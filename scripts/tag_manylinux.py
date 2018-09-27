from auditwheel.wheeltools import InWheelCtx, add_platforms
import click
import os


@click.command()
@click.argument('wheel',  type=click.Path(exists=True))
def main(wheel):
  dir = os.path.dirname(os.path.abspath(wheel))
  with InWheelCtx(wheel) as ctx:
    try:
      new_wheel = add_platforms(ctx, ['manylinux1_x86_64'], remove_platforms=('linux_x86_64',))
    except WheelToolsError as e:
      click.echo(str(e), err=True)
      raise
    if new_wheel:
      ctx.out_wheel = os.path.normpath(os.path.join(dir, new_wheel))
      click.echo('Updated wheel written to %s' % ctx.out_wheel)

if __name__ == "__main__":
  main()
 