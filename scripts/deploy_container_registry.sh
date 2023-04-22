dir=$(basename "$(pwd)")
if [ "$dir" == "scripts" ]; then
cd ..
fi

app_image="$DOCKER_REGISTRY/chefbook-backend-auth"
migrations_image="$app_image-migrations"

read -rp 'Enter version tag: ' tag
app_tags="-t $app_image:$tag"
migrations_tags="-t $migrations_image:$tag"

read -rp 'Latest release (empty for non): ' latest
if [[ $latest ]]; then
  app_tags="$app_tags -t $app_image:latest"
  migrations_tags="$migrations_tags -t $migrations_image:latest"

  read -rp 'Stable release (empty for debug): ' stable
  if [[ $stable ]]; then
  app_tags="$app_tags -t $app_image:stable"
  migrations_tags="$migrations_tags -t $migrations_image:stable"
  else
  app_tags="$app_tags -t $app_image:debug"
  migrations_tags="$migrations_tags -t $migrations_image:debug"
  fi
fi

docker build -f Dockerfile $app_tags . && docker push --all-tags "$app_image"

docker build -f migrations/Dockerfile $migrations_tags . && docker push --all-tags "$migrations_image"
