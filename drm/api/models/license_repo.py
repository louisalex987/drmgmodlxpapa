from shared.models import license_repo as shared_license_repo

generate_license = shared_license_repo.generate_license
regenerate_license = shared_license_repo.regenerate_license
deactivate_old_keys = shared_license_repo.deactivate_old_keys
validate_license = shared_license_repo.validate_license
log_usage = shared_license_repo.log_usage
get_license = shared_license_repo.get_license
list_all = shared_license_repo.list_all
for_client = shared_license_repo.for_client