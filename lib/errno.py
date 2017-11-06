import '__go__/syscall'


for name in dir(syscall):
  value = getattr(syscall, name)
  if isinstance(value, syscall.Errno):
    globals()[name] = value
