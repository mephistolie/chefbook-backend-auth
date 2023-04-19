read -rp 'Enter tag: ' tag
apiTag="api/$tag"

git tag "$tag"
git push origin "$tag"

git tag "$apiTag"
git push origin "$apiTag"
