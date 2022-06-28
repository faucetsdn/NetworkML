FROM networkml
LABEL maintainer="Ryan Ashley <rashley@iqt.org>"

ENTRYPOINT ["networkml"]
CMD ["--trained_model=/trained_models/host_footprint.json", "--label_encoder=/trained_models/host_footprint_le.json", "--scaler=/trained_models/host_footprint_scaler.mod", "--operation", "predict", "/pcaps"]