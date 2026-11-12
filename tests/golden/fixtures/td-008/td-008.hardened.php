<?php

$project = Project::where('organization_id', $user->organization_id)
    ->findOrFail($request->input('project_id'));
