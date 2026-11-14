<?php

class SubscriptionController
{
    // ❌ FLAW (Laravel): billing tier taken straight from the client's request.
    public function activate(Request $request)
    {
        $user = User::find($request->user()->id);
        $user->update([
            'billing_tier' => $request->input('tier'),
            'is_active' => true,
        ]);
    }
}
