Math.initialize() do $4
   prepend dup
   4.instance_exec(){|| super() }
end