dir=$(basename "$(pwd)")
if [ "$dir" == "scripts" ]; then
  cd ..
fi

# Configuration

app_name=chefbook-backend-auth-service
app_image="$CONTAINER_REGISTRY/$app_name"
migrations_image="$app_image-migrations"

read -rp 'Enter version: ' version
app_tags="-t $app_image:$version"
migrations_tags="-t $migrations_image:$version"

latest=""
while [[ $latest != "y" ]] && [[ $latest != "n" ]]; do
  read -rp 'Latest release (y/n): ' latest
done

if [[ $latest == "y" ]]; then
  app_tags="$app_tags -t $app_image:latest"
  migrations_tags="$migrations_tags -t $migrations_image:latest"

  release=""
  while [[ $release != "d" ]] && [[ $release != "s" ]]; do
    read -rp 'Release type (d/s): ' release
  done

  if [[ $release == "s" ]]; then
    app_tags="$app_tags -t $app_image:stable"
    migrations_tags="$migrations_tags -t $migrations_image:stable"
  else
    app_tags="$app_tags -t $app_image:debug"
    migrations_tags="$migrations_tags -t $migrations_image:debug"
  fi
fi

echo $'\nCONFIGURATION'
echo "Version: $version"
echo "Latest: $latest"
if [[ $latest == "y" ]]; then
  echo "Release: $release"
fi
read -rp "Confirm (only yes will be accepted): " confirm
if [[ $confirm != "yes" ]]; then
  exit
fi
echo

# Containers

docker build --platform linux/amd64 -f Dockerfile $app_tags . && docker push --all-tags "$app_image"
docker build --platform linux/amd64 -f migrations/Dockerfile $migrations_tags . && docker push --all-tags "$migrations_image"

# Helm Chart

repositoryAlias=@chefbook-helm-repository
repositoryUrl=oci://$HELM_REGISTRY
chartArchive="$app_name-$version.tgz"

cd deployments/helm || exit

sed -i '' "s,$repositoryAlias,$repositoryUrl,g" Chart.yaml

helm dependency update
helm package . --version "$version"
helm push "$chartArchive" "$repositoryUrl"

rm "$chartArchive"
sed -i '' "s,$repositoryUrl,$repositoryAlias,g" Chart.yaml
