<?php

class SubscriptionController
{
    // ✅ HARDENED (Laravel): tier derived from the provider-verified plan.
    public function activate(Request $request)
    {
        $planId = $this->paypal->getSubscription($request->input('subscription_id'))->plan_id;
        $tier = $this->tierForPlan($planId);
        $user = User::find($request->user()->id);
        $user->update([
            'billing_tier' => $tier,
            'is_active' => true,
        ]);
    }
}
